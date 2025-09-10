package shit

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"shit/internal/config"
)

type CLI struct {
	config         *config.ShitCLIConfig
	conn           net.Conn
	reader         *bufio.Reader
	writer         *bufio.Writer
	currentSession int64
	sessionHistory map[int64][]string // Command history per session
	historyIndex   int                // Current position in history
}

func NewCLI(cfg *config.ShitCLIConfig) *CLI {
	return &CLI{
		config:         cfg,
		sessionHistory: make(map[int64][]string),
		historyIndex:   -1,
	}
}

func (c *CLI) Run() error {
	if err := c.connect(); err != nil {
		return fmt.Errorf("failed to connect to shit-server: %w", err)
	}
	defer c.disconnect()

	fmt.Println("Connected to shit-server")

	if err := c.showSessionMenu(); err != nil {
		fmt.Printf("Error: %v\n", err)
	}

	c.currentSession = 0

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT)

	go func() {
		for range sigChan {
			if c.currentSession > 0 {
				c.sendInterrupt()
			} else {
				fmt.Println("\nGoodbye!")
				os.Exit(0)
			}
		}
	}()

	for {
		prompt := "shit> "
		if c.currentSession > 0 {
			prompt = fmt.Sprintf("shit[%d]> ", c.currentSession)
		}

		input, err := c.readLineWithHistory(prompt)
		if err != nil {
			if err == io.EOF {
				break
			}
			if err.Error() == "interrupted" {
				if c.currentSession == 0 {
					fmt.Println("Goodbye!")
					break
				}
				continue
			}
			fmt.Printf("Error reading input: %v\n", err)
			continue
		}

		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		if c.currentSession > 0 && !strings.HasPrefix(input, "/") {
			c.addToHistory(c.currentSession, input)
		}

		if err := c.handleCommand(input); err != nil {
			fmt.Printf("Error: %v\n", err)
		}

	}

	return nil
}

func (c *CLI) connect() error {
	conn, err := net.Dial("unix", c.config.SocketPath)
	if err != nil {
		return err
	}

	c.conn = conn
	c.reader = bufio.NewReader(conn)
	c.writer = bufio.NewWriter(conn)

	return nil
}

func (c *CLI) disconnect() {
	if c.conn != nil {
		c.conn.Close()
	}
}

func (c *CLI) handleCommand(input string) error {
	parts := strings.Fields(input)
	if len(parts) == 0 {
		return nil
	}

	command := parts[0]
	args := parts[1:]

	switch command {
	case "/help", "/h":
		c.printHelp()

	case "/list", "/ls":
		return c.listSessions()

	case "/menu":
		return c.showSessionMenu()

	case "/connect", "/c":
		if len(args) < 1 {
			return fmt.Errorf("usage: /connect <session-id>")
		}
		sessionID, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid session ID: %v", err)
		}
		return c.connectToTTY(sessionID)

	case "/q", "/quit", "/exit":
		if c.currentSession == 0 {
			fmt.Println("Goodbye!")
			os.Exit(0)
		}
		fmt.Printf("Disconnected from session %d\n", c.currentSession)
		c.currentSession = 0
		c.historyIndex = -1

	default:
		if c.currentSession > 0 {
			return c.execCommand(input)
		}
		if !strings.HasPrefix(command, "/") {
			return fmt.Errorf("not connected to any session. Use /help for available commands")
		}
		return fmt.Errorf("unknown command: %s", command)
	}

	return nil
}

func (c *CLI) printHelp() {
	fmt.Println("\n======== shit CLI Commands ========")
	fmt.Println("All commands starting with / are local to shit")
	fmt.Println()
	fmt.Println("  /help, /h          - Show this help message")
	fmt.Println("  /list, /ls         - List active sessions")
	fmt.Println("  /menu              - Show session selection menu")
	fmt.Println("  /connect, /c <id>  - Connect to a specific session")
	fmt.Println("  /q, /quit, /exit   - Disconnect from session (or exit if not connected)")
	fmt.Println()
	fmt.Println("When connected to a session:")
	fmt.Println("  - Any text WITHOUT / is sent to the remote shell")
	fmt.Println("  - Use /q to disconnect from current session")
	fmt.Println("  - Press Ctrl+C to interrupt a running command")
	fmt.Println()
}

func (c *CLI) showSessionMenu() error {
	req := map[string]interface{}{
		"method": "list",
	}

	if err := c.sendRequest(req); err != nil {
		return err
	}

	resp, err := c.receiveResponse()
	if err != nil {
		return err
	}

	sessions, ok := resp["sessions"].([]interface{})
	if !ok {
		return fmt.Errorf("invalid response format")
	}

	if len(sessions) == 0 {
		fmt.Println("\nNo active sessions available.")
		fmt.Println("Waiting for shit clients to connect...")
		fmt.Println("\nType /list to refresh sessions or /help for commands")
		fmt.Println()
		return nil
	}

	fmt.Println("\n========================================")
	fmt.Println("         Available Sessions")
	fmt.Println("========================================")

	sessionIDs := make([]int64, 0, len(sessions))

	for i, s := range sessions {
		session := s.(map[string]interface{})
		id := int64(session["id"].(float64))
		address := session["address"].(string)
		hostname, _ := session["hostname"].(string)

		sessionIDs = append(sessionIDs, id)
		if hostname != "" {
			fmt.Printf(" [%d] Session %d - %s (%s)\n", i+1, id, hostname, address)
		} else {
			fmt.Printf(" [%d] Session %d - %s\n", i+1, id, address)
		}
	}

	fmt.Println("========================================")
	fmt.Println(" [0] Continue without connecting")
	fmt.Println("========================================")

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("\nSelect session (0-" + strconv.Itoa(len(sessions)) + "): ")

	input, err := reader.ReadString('\n')
	if err != nil {
		return err
	}

	choice, err := strconv.Atoi(strings.TrimSpace(input))
	if err != nil || choice < 0 || choice > len(sessions) {
		fmt.Println("Invalid selection")
		return nil
	}

	if choice == 0 {
		fmt.Println("\nEntering command mode. Type /help for available commands.")
		fmt.Println()
		return nil
	}

	sessionID := sessionIDs[choice-1]

	if err := c.connectToTTY(sessionID); err != nil {
		fmt.Printf("Failed to connect to TTY: %v\n", err)
		return err
	}

	fmt.Println("\nTTY session ended. Entering command mode.")
	return nil
}

func (c *CLI) listSessions() error {
	req := map[string]interface{}{
		"method": "list",
	}

	if err := c.sendRequest(req); err != nil {
		return err
	}

	resp, err := c.receiveResponse()
	if err != nil {
		return err
	}

	sessions, ok := resp["sessions"].([]interface{})
	if !ok {
		return fmt.Errorf("invalid response format")
	}

	if len(sessions) == 0 {
		fmt.Println("No active sessions")
		return nil
	}

	fmt.Println("\nActive sessions:")
	fmt.Printf("%-10s %-20s %-30s %-20s\n", "ID", "Hostname", "Address", "Last Ping")
	fmt.Println(strings.Repeat("-", 80))

	for _, s := range sessions {
		session := s.(map[string]interface{})
		id := int64(session["id"].(float64))
		address := session["address"].(string)
		hostname, _ := session["hostname"].(string)
		lastPing := int64(session["lastPing"].(float64))

		if hostname == "" {
			hostname = "unknown"
		}

		fmt.Printf("%-10d %-20s %-30s %d\n", id, hostname, address, lastPing)
	}
	fmt.Println()

	return nil
}

func (c *CLI) execCommand(command string) error {
	req := map[string]interface{}{
		"method":    "exec",
		"sessionId": c.currentSession,
		"command":   command,
	}

	if err := c.sendRequest(req); err != nil {
		return err
	}

	resp, err := c.receiveResponse()
	if err != nil {
		return err
	}

	if errMsg, ok := resp["error"].(string); ok {
		return fmt.Errorf(errMsg)
	}

	if msgType, ok := resp["type"].(string); ok && msgType == "start" {
		fmt.Print("\r")

		for {
			outputResp, err := c.receiveResponse()
			if err != nil {
				return err
			}

			msgType, ok := outputResp["type"].(string)
			if !ok {
				continue
			}

			switch msgType {
			case "output":
				if data, ok := outputResp["data"].(string); ok {
					fmt.Print(data)

					if strings.Contains(strings.ToLower(data), "password") &&
						(strings.HasSuffix(strings.TrimSpace(data), ":") || strings.HasSuffix(strings.TrimSpace(data), ": ")) {

						reader := bufio.NewReader(os.Stdin)
						input, err := reader.ReadString('\n')
						if err == nil {
							c.sendStdinInput(input)
						}
					}
				}
			case "end":
				return nil
			case "error":
				if errMsg, ok := outputResp["error"].(string); ok {
					return fmt.Errorf(errMsg)
				}
				return fmt.Errorf("command execution error")
			}
		}
	}

	return nil
}

func (c *CLI) sendInterrupt() error {
	if c.currentSession == 0 {
		return nil
	}

	req := map[string]interface{}{
		"method":    "interrupt",
		"sessionId": c.currentSession,
	}

	if err := c.sendRequest(req); err != nil {
		return err
	}

	resp, err := c.receiveResponse()
	if err != nil {
		return err
	}

	if errMsg, ok := resp["error"].(string); ok {
		return fmt.Errorf(errMsg)
	}

	fmt.Println("\n^C")
	return nil
}

func (c *CLI) sendRequest(req map[string]interface{}) error {
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}

	if _, err := c.writer.Write(data); err != nil {
		return err
	}
	if _, err := c.writer.WriteString("\n"); err != nil {
		return err
	}
	return c.writer.Flush()
}

func (c *CLI) receiveResponse() (map[string]interface{}, error) {
	line, err := c.reader.ReadBytes('\n')
	if err != nil {
		return nil, err
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(bytes.TrimSpace(line), &resp); err != nil {
		return nil, err
	}

	return resp, nil
}

func (c *CLI) addToHistory(sessionID int64, command string) {
	if _, exists := c.sessionHistory[sessionID]; !exists {
		c.sessionHistory[sessionID] = make([]string, 0)
	}

	history := c.sessionHistory[sessionID]
	if len(history) > 0 && history[len(history)-1] == command {
		return
	}

	c.sessionHistory[sessionID] = append(c.sessionHistory[sessionID], command)

	if len(c.sessionHistory[sessionID]) > 100 {
		c.sessionHistory[sessionID] = c.sessionHistory[sessionID][1:]
	}
}

func (c *CLI) readLineWithHistory(prompt string) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Print(prompt)
		reader := bufio.NewReader(os.Stdin)
		return reader.ReadString('\n')
	}

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Print(prompt)
		reader := bufio.NewReader(os.Stdin)
		return reader.ReadString('\n')
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	fmt.Print(prompt)

	var line []rune
	var cursor int
	c.historyIndex = -1

	history := []string{}
	if c.currentSession > 0 {
		if sessionHistory, exists := c.sessionHistory[c.currentSession]; exists {
			history = sessionHistory
		}
	}

	for {
		var buf [1]byte
		n, err := os.Stdin.Read(buf[:])
		if err != nil {
			return "", err
		}
		if n == 0 {
			continue
		}

		b := buf[0]

		switch b {
		case 3:
			fmt.Println("^C")
			return "", fmt.Errorf("interrupted")

		case 4:
			if len(line) == 0 {
				return "", io.EOF
			}

		case 13:
			fmt.Print("\r\n")
			return string(line), nil

		case 127:
			if cursor > 0 {
				line = append(line[:cursor-1], line[cursor:]...)
				cursor--
				c.redrawLine(prompt, line, cursor)
			}

		case 27:
			var seq [2]byte
			os.Stdin.Read(seq[:])

			if seq[0] == 91 {
				switch seq[1] {
				case 65:
					if len(history) > 0 {
						if c.historyIndex == -1 {
							c.historyIndex = len(history) - 1
						} else if c.historyIndex > 0 {
							c.historyIndex--
						}
						if c.historyIndex >= 0 && c.historyIndex < len(history) {
							line = []rune(history[c.historyIndex])
							cursor = len(line)
							c.redrawLine(prompt, line, cursor)
						}
					}

				case 66:
					if len(history) > 0 && c.historyIndex >= 0 {
						if c.historyIndex < len(history)-1 {
							c.historyIndex++
							line = []rune(history[c.historyIndex])
							cursor = len(line)
							c.redrawLine(prompt, line, cursor)
						} else {
							c.historyIndex = -1
							line = []rune{}
							cursor = 0
							c.redrawLine(prompt, line, cursor)
						}
					}

				case 67:
					if cursor < len(line) {
						cursor++
						fmt.Print("\033[C")
					}

				case 68:
					if cursor > 0 {
						cursor--
						fmt.Print("\033[D")
					}
				}
			}

		default:
			if b >= 32 && b < 127 {
				line = append(line[:cursor], append([]rune{rune(b)}, line[cursor:]...)...)
				cursor++
				c.redrawLine(prompt, line, cursor)
			}
		}
	}
}

func (c *CLI) sendStdinInput(input string) error {
	req := map[string]interface{}{
		"method":    "stdin",
		"sessionId": c.currentSession,
		"data":      input,
	}

	if err := c.sendRequest(req); err != nil {
		return err
	}

	// Read and ignore response
	_, err := c.receiveResponse()
	return err
}

func (c *CLI) redrawLine(prompt string, line []rune, cursor int) {
	fmt.Print("\r\033[K")
	fmt.Print(prompt)
	fmt.Print(string(line))

	if cursor < len(line) {
		fmt.Printf("\033[%dD", len(line)-cursor)
	}
}

func (c *CLI) connectToTTY(sessionID int64) error {
	req := map[string]interface{}{
		"method":    "connect",
		"sessionId": sessionID,
	}

	if err := c.sendRequest(req); err != nil {
		return fmt.Errorf("failed to send connect request: %w", err)
	}

	resp, err := c.receiveResponse()
	if err != nil {
		return fmt.Errorf("failed to receive response: %w", err)
	}

	success, _ := resp["success"].(bool)
	if !success {
		errorMsg, _ := resp["error"].(string)
		return fmt.Errorf("failed to connect to session: %s", errorMsg)
	}

	fmt.Printf("\rConnected to TTY session %d. Use Ctrl+] to disconnect.\n\r", sessionID)

	return c.enterTTYMode(sessionID)
}

func (c *CLI) enterTTYMode(sessionID int64) error {
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("failed to enter raw mode: %w", err)
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	resizeChan := make(chan os.Signal, 1)
	signal.Notify(resizeChan, syscall.SIGWINCH)
	go func() {
		for range resizeChan {
			c.sendTerminalResize(sessionID)
		}
	}()
	defer signal.Stop(resizeChan)

	c.sendTerminalResize(sessionID)

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- c.readTTYFromServer()
	}()

	stdinDone := make(chan error, 1)
	go func() {
		stdinDone <- c.writeTTYToServer(sessionID)
	}()

	select {
	case err := <-serverDone:
		fmt.Printf("\nTTY connection closed by server: %v\n", err)
	case err := <-stdinDone:
		fmt.Printf("\nTTY connection closed: %v\n", err)
	}

	return nil
}

func (c *CLI) readTTYFromServer() error {
	if tcpConn, ok := c.conn.(*net.UnixConn); ok {
		tcpConn.SetReadDeadline(time.Time{})
	}

	for {
		if tcpConn, ok := c.conn.(*net.UnixConn); ok {
			tcpConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		}

		line, err := c.reader.ReadBytes('\n')
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return err
		}

		var msg map[string]interface{}
		if err := json.Unmarshal(bytes.TrimSpace(line), &msg); err != nil {
			continue
		}

		method, _ := msg["method"].(string)

		if method == "tty:data" {
			body, _ := msg["body"].(map[string]interface{})
			if body != nil {
				if dataStr, ok := body["data"].(string); ok {
					data, err := base64.StdEncoding.DecodeString(dataStr)
					if err == nil {
						os.Stdout.Write(data)
						os.Stdout.Sync()
					}
				}
			}
		}
	}
}

func (c *CLI) writeTTYToServer(sessionID int64) error {
	buf := make([]byte, 256)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil {
			return err
		}

		if n > 0 {
			for i := 0; i < n; i++ {
				if buf[i] == 29 {
					return fmt.Errorf("disconnected by user")
				}
			}
			msg := map[string]interface{}{
				"id":     sessionID,
				"method": "tty:data",
				"body": map[string]interface{}{
					"data": buf[:n],
				},
			}

			data, err := json.Marshal(msg)
			if err != nil {
				return err
			}

			if _, err := c.conn.Write(data); err != nil {
				return err
			}
			if _, err := c.conn.Write([]byte("\n")); err != nil {
				return err
			}

			if c.writer != nil {
				c.writer.Flush()
			}
		}
	}
}

func (c *CLI) sendTerminalResize(sessionID int64) error {
	width, height, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		return err
	}
	msg := map[string]interface{}{
		"id":     sessionID,
		"method": "tty:resize",
		"body": map[string]interface{}{
			"cols": width,
			"rows": height,
		},
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	if _, err := c.conn.Write(data); err != nil {
		return err
	}
	if _, err := c.conn.Write([]byte("\n")); err != nil {
		return err
	}

	return nil
}
