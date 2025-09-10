package shitshell

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"

	"shit/internal/config"
	"shit/internal/crypto"
	"shit/internal/protocol"
)

type Client struct {
	config       *config.ShitConfig
	pskManager   *crypto.PSKManager
	conn         net.Conn
	sessionID    int64
	pingTicker   *time.Ticker
	pingFailures int
	mu           sync.Mutex
	reader       *bufio.Reader
	writer       *bufio.Writer
	currentPSK   string // Store current PSK for encryption

	// TTY components
	ptyFile          *os.File
	shell            *exec.Cmd
	ttyActive        bool
	outputForwarding bool
}

func NewClient(cfg *config.ShitConfig) *Client {
	return &Client{
		config:     cfg,
		pskManager: crypto.NewPSKManager(cfg.KeysFile),
	}
}

func (c *Client) Run() error {
	if err := c.pskManager.LoadKeys(); err != nil {
		return fmt.Errorf("failed to load keys: %w", err)
	}

	for {
		if err := c.connect(); err != nil {
			log.Printf("Connection failed: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		if err := c.handleConnection(); err != nil {
			log.Printf("Connection error: %v", err)
		}

		c.disconnect()
		time.Sleep(5 * time.Second)
	}
}

func (c *Client) connect() error {
	addr := net.JoinHostPort(c.config.ServerAddr, fmt.Sprintf("%d", c.config.ServerPort))
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}

	c.conn = conn
	c.reader = bufio.NewReader(conn)
	c.writer = bufio.NewWriter(conn)

	c.sessionID = 0
	c.currentPSK = ""

	localIP := conn.LocalAddr().(*net.TCPAddr).IP.String()
	hostname, _ := os.Hostname()
	keyID := fmt.Sprintf("%s:%s", c.config.ServerAddr, hostname)

	psk, exists := c.pskManager.GetKey(keyID)

	if !exists {
		if err := c.performKeyExchange(localIP); err != nil {
			conn.Close()
			return err
		}
	} else {
		c.currentPSK = psk
		if err := c.sendAuth(psk, hostname); err != nil {
			conn.Close()
			return err
		}
	}

	return c.startSession()
}

func (c *Client) performKeyExchange(clientIP string) error {
	hostname, _ := os.Hostname()
	req := protocol.KeyExchangeRequest{
		ClientIP: clientIP,
		Hostname: hostname,
	}
	msg, _ := protocol.NewMessage(0, "key:exchange", req)

	if err := c.sendMessage(msg); err != nil {
		return err
	}

	// Key exchange response comes as plain text
	resp, err := c.receiveMessage()
	if err != nil {
		return err
	}

	if resp.Method != "key:exchange:response" {
		return fmt.Errorf("unexpected response: %s", resp.Method)
	}

	var keyResp protocol.KeyExchangeResponse
	if err := resp.UnmarshalBody(&keyResp); err != nil {
		return err
	}

	if !crypto.ValidatePSK(keyResp.PSK) {
		return fmt.Errorf("invalid PSK received")
	}

	hostname2, _ := os.Hostname()
	keyID := fmt.Sprintf("%s:%s", c.config.ServerAddr, hostname2)
	if err := c.pskManager.SetKey(keyID, keyResp.PSK); err != nil {
		return err
	}
	c.currentPSK = keyResp.PSK
	return nil
}

func (c *Client) sendAuth(psk string, hostname string) error {
	authReqBody := protocol.AuthRequestBody{
		Hostname: hostname,
	}
	tempPSK := c.currentPSK
	c.currentPSK = ""

	msg, _ := protocol.NewMessage(0, "auth_request", authReqBody)
	if err := c.sendMessage(msg); err != nil {
		c.currentPSK = tempPSK
		return err
	}

	c.currentPSK = tempPSK

	hashedPSK := crypto.HashPSK(psk)
	authBody := protocol.AuthBody{
		PSK:      hashedPSK,
		Hostname: hostname,
	}
	authMsg, _ := protocol.NewMessage(0, "auth", authBody)

	return c.sendMessage(authMsg)
}

func (c *Client) startSession() error {
	hostname, _ := os.Hostname()
	startBody := protocol.StartBody{
		Hostname: hostname,
	}
	msg, _ := protocol.NewMessage(0, "start", startBody)
	if err := c.sendMessage(msg); err != nil {
		return err
	}

	resp, err := c.receiveMessage()
	if err != nil {
		return err
	}

	if resp.Method != "start:confirm" {
		return fmt.Errorf("failed to start session")
	}

	var body protocol.StartConfirmBody
	if err := resp.UnmarshalBody(&body); err != nil {
		return err
	}

	c.sessionID = body.SessionID
	c.startPing()
	return nil
}

func (c *Client) handleConnection() error {
	defer c.stopPing()

	for {
		msg, err := c.receiveMessage()
		if err != nil {
			if err == io.EOF {
				log.Printf("Server connection lost, TTY will continue running")
				return fmt.Errorf("connection closed by server")
			}
			return err
		}

		switch msg.Method {
		case "pong":
			c.handlePong()
		case "tty:start":
			log.Printf("Starting fresh TTY session")
			go c.startTTY()
		case "tty:data":
			c.handleTTYData(msg)
		case "tty:resize":
			c.handleTTYResize(msg)
		}
	}
}

func (c *Client) startTTY() {
	c.mu.Lock()
	if c.ttyActive && c.ptyFile != nil && c.shell != nil && c.shell.Process != nil {
		err := c.shell.Process.Signal(syscall.Signal(0))
		if err == nil {
			log.Printf("TTY is already active and healthy, skipping restart")
			c.mu.Unlock()
			return
		}
	}

	if c.ptyFile != nil {
		c.ptyFile.Close()
		c.ptyFile = nil
	}
	if c.shell != nil && c.shell.Process != nil {
		c.shell.Process.Kill()
	}
	c.shell = nil
	c.ttyActive = false
	c.outputForwarding = false
	c.mu.Unlock()

	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "/"
	}

	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/bash"
	}

	c.shell = exec.Command(shell)
	c.shell.Dir = homeDir
	c.shell.Env = os.Environ()

	ptyFile, err := pty.Start(c.shell)
	if err != nil {
		log.Printf("Failed to start PTY: %v", err)
		return
	}

	c.mu.Lock()
	c.ptyFile = ptyFile
	c.ttyActive = true
	c.outputForwarding = true
	c.mu.Unlock()

	log.Printf("TTY started with shell: %s in %s", shell, homeDir)

	go c.forwardPTYOutput()

	go c.monitorShellProcess()

	go func() {
		time.Sleep(100 * time.Millisecond)
		c.mu.Lock()
		if c.ptyFile != nil && c.ttyActive {
			pty.Setsize(c.ptyFile, &pty.Winsize{
				Rows: 24,
				Cols: 80,
			})
		}
		c.mu.Unlock()
	}()
}

func (c *Client) forwardPTYOutput() {
	c.mu.Lock()
	if c.ptyFile == nil || !c.outputForwarding {
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()

	buf := make([]byte, 1024)
	for c.ttyActive {
		c.mu.Lock()
		ptyFile := c.ptyFile
		ttyActive := c.ttyActive
		c.mu.Unlock()

		if !ttyActive || ptyFile == nil {
			break
		}

		n, err := ptyFile.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("PTY read error: %v", err)
			}
			go c.triggerTTYCleanup()
			break
		}

		if n > 0 {
			msg, _ := protocol.NewMessage(c.sessionID, "tty:data", protocol.TTYDataBody{
				Data: buf[:n],
			})
			if err := c.sendMessage(msg); err != nil {
				log.Printf("Connection lost, stopping PTY output forwarding")
				break
			}
		}
	}
	log.Printf("PTY output forwarding stopped")
}

func (c *Client) handleTTYData(msg *protocol.Message) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.ttyActive || c.ptyFile == nil || c.shell == nil || c.shell.Process == nil || !c.isShellProcessAlive() {
		return
	}

	var body protocol.TTYDataBody
	if err := msg.UnmarshalBody(&body); err != nil {
		log.Printf("Failed to unmarshal TTY data: %v", err)
		return
	}

	c.ptyFile.Write(body.Data)
}

func (c *Client) handleTTYResize(msg *protocol.Message) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.ttyActive || c.ptyFile == nil || c.shell == nil || c.shell.Process == nil || !c.isShellProcessAlive() {
		return
	}

	var body protocol.TTYResizeBody
	if err := msg.UnmarshalBody(&body); err != nil {
		log.Printf("Failed to unmarshal TTY resize: %v", err)
		return
	}

	if err := pty.Setsize(c.ptyFile, &pty.Winsize{
		Rows: uint16(body.Rows),
		Cols: uint16(body.Cols),
	}); err != nil {
		log.Printf("Failed to resize PTY: %v", err)
	}
}

func (c *Client) cleanupTTY() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.ttyActive {
		c.ttyActive = false
		if c.ptyFile != nil {
			c.ptyFile.Close()
			c.ptyFile = nil
		}
		if c.shell != nil && c.shell.Process != nil {
			c.shell.Process.Kill()
			c.shell = nil
		}
	}
}

func (c *Client) startPing() {
	c.pingTicker = time.NewTicker(1 * time.Second)
	c.pingFailures = 0

	go func() {
		for range c.pingTicker.C {
			msg, _ := protocol.NewMessage(c.sessionID, "ping", nil)
			if err := c.sendMessage(msg); err != nil {
				c.pingFailures++
				if c.pingFailures >= 5 {
					c.disconnect()
					return
				}
			}
		}
	}()
}

func (c *Client) stopPing() {
	if c.pingTicker != nil {
		c.pingTicker.Stop()
	}
}

func (c *Client) handlePong() {
	c.pingFailures = 0
}

func (c *Client) sendMessage(msg *protocol.Message) error {
	data, err := msg.Marshal()
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.writer == nil {
		return fmt.Errorf("connection not established")
	}

	var finalData []byte
	if c.currentPSK != "" {
		encryptedData, err := crypto.EncryptMessage(c.currentPSK, data)
		if err != nil {
			return fmt.Errorf("encryption failed: %w", err)
		}
		finalData = encryptedData
	} else {
		finalData = data
	}

	if _, err := c.writer.Write(finalData); err != nil {
		return err
	}
	if _, err := c.writer.WriteString("\n"); err != nil {
		return err
	}
	return c.writer.Flush()
}

func (c *Client) receiveMessage() (*protocol.Message, error) {
	if c.reader == nil {
		return nil, fmt.Errorf("connection not established")
	}

	line, err := c.reader.ReadBytes('\n')
	if err != nil {
		return nil, err
	}

	line = bytes.TrimSpace(line)

	var messageData []byte
	if c.currentPSK != "" {
		decryptedData, err := crypto.DecryptMessage(c.currentPSK, line)
		if err != nil {
			if c.sessionID == 0 {
				messageData = line
			} else {
				return nil, fmt.Errorf("failed to decrypt message in established session: %w", err)
			}
		} else {
			messageData = decryptedData
		}
	} else {
		messageData = line
	}

	return protocol.UnmarshalMessage(messageData)
}

func (c *Client) disconnect() {
	c.stopPing()
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
		c.reader = nil
		c.writer = nil
	}

	c.currentPSK = ""
	c.sessionID = 0
	c.pingFailures = 0
}

func (c *Client) isShellProcessAlive() bool {
	if c.shell == nil || c.shell.Process == nil {
		return false
	}

	err := c.shell.Process.Signal(syscall.Signal(0))
	return err == nil
}

func (c *Client) triggerTTYCleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.ttyActive {
		log.Printf("Triggering immediate TTY cleanup due to PTY error")
		c.ttyActive = false
		c.outputForwarding = false
		if c.ptyFile != nil {
			c.ptyFile.Close()
			c.ptyFile = nil
		}
	}
}

func (c *Client) monitorShellProcess() {
	if c.shell == nil || c.shell.Process == nil {
		return
	}

	err := c.shell.Wait()

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.ttyActive {
		c.ttyActive = false
		c.outputForwarding = false
		if c.ptyFile != nil {
			c.ptyFile.Close()
			c.ptyFile = nil
		}
		c.shell = nil

		if err != nil {
			log.Printf("Shell process exited with error: %v - TTY session terminated", err)
		} else {
			log.Printf("Shell process exited normally - TTY session terminated")
		}
	}
}
