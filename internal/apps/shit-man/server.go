package shitman

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"shit/internal/config"
	"shit/internal/crypto"
	"shit/internal/protocol"
)

var debugLogger *log.Logger
var debugEnabled bool

func init() {
	debugEnabled = strings.ToLower(os.Getenv("SHIT_SERVER_DEBUG_LOG")) == "true"

	if debugEnabled {
		os.MkdirAll("logs", 0755)

		debugFile, err := os.OpenFile("logs/debug.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Printf("Failed to open debug.log: %v", err)
			debugLogger = log.New(os.Stdout, "[DEBUG] ", log.LstdFlags)
		} else {
			debugLogger = log.New(debugFile, "[DEBUG] ", log.LstdFlags)
		}
	} else {
		debugLogger = log.New(io.Discard, "", 0)
	}
}

type Session struct {
	ID         int64
	ClientAddr string
	Hostname   string
	Conn       net.Conn
	Reader     *bufio.Reader
	Writer     *bufio.Writer
	PSK        string
	LastPing   time.Time
	TTYClients map[net.Conn]bool // Connected shit clients for TTY forwarding
	mu         sync.Mutex
}

type Server struct {
	config       *config.ShitServerConfig
	pskManager   *crypto.PSKManager
	sessions     map[int64]*Session
	sessionMu    sync.RWMutex
	nextID       int64
	listener     net.Listener
	sockListener net.Listener
}

func NewServer(cfg *config.ShitServerConfig) *Server {
	return &Server{
		config:     cfg,
		pskManager: crypto.NewPSKManager(cfg.AuthorizedKeys),
		sessions:   make(map[int64]*Session),
	}
}

func (s *Server) Run() error {
	if err := s.pskManager.LoadKeys(); err != nil {
		return fmt.Errorf("failed to load keys: %w", err)
	}

	go s.cleanupSessions()

	if err := s.startSocketListener(); err != nil {
		return err
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", s.config.ListenAddr, s.config.ListenPort))
	if err != nil {
		return err
	}
	s.listener = listener

	log.Printf("Shit server listening on %s:%d", s.config.ListenAddr, s.config.ListenPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

func (s *Server) startSocketListener() error {
	os.Remove(s.config.SocketPath)

	listener, err := net.Listen("unix", s.config.SocketPath)
	if err != nil {
		return err
	}

	s.sockListener = listener

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("Socket accept error: %v", err)
				continue
			}
			go s.handleSocketConnection(conn)
		}
	}()

	return nil
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()
	clientIP := strings.Split(clientAddr, ":")[0]

	log.Printf("Shit client connecting from %s", clientAddr)
	debugLogger.Printf("New connection attempt from %s (IP: %s)", clientAddr, clientIP)

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	msg, err := s.receiveMessage(reader)
	if err != nil {
		log.Printf("Failed to receive initial message: %v", err)
		return
	}

	var session *Session
	var hostname string

	if msg.Method == "key:exchange" {
		psk, hn, err := s.handleKeyExchange(clientIP, msg, writer)
		if err != nil {
			log.Printf("Key exchange failed: %v", err)
			return
		}
		hostname = hn
		session = &Session{
			ClientAddr: clientAddr,
			Hostname:   hostname,
			Conn:       conn,
			Reader:     reader,
			Writer:     writer,
			PSK:        psk,
			TTYClients: make(map[net.Conn]bool),
		}
	} else if msg.Method == "auth_request" {
		var authReqBody protocol.AuthRequestBody
		if err := msg.UnmarshalBody(&authReqBody); err != nil {
			log.Printf("Failed to unmarshal auth_request: %v", err)
			return
		}

		hostname = authReqBody.Hostname

		keyID := fmt.Sprintf("%s:%s", clientIP, hostname)
		psk, exists := s.pskManager.GetKey(keyID)

		if !exists {
			log.Printf("Authentication failed: No PSK found for %s:%s", clientIP, hostname)
			debugLogger.Printf("Authentication attempt failed - no PSK found for %s:%s", clientIP, hostname)
			return
		}
		encryptedMsg, err := s.receiveMessageWithDecryption(reader, psk)
		if err != nil {
			log.Printf("Failed to receive encrypted auth message: %v", err)
			debugLogger.Printf("Failed to decrypt message: %v", err)
			return
		}

		if encryptedMsg.Method != "auth" {
			log.Printf("Expected auth message, got: %s", encryptedMsg.Method)
			return
		}

		var authBody protocol.AuthBody
		if err := encryptedMsg.UnmarshalBody(&authBody); err != nil {
			log.Printf("Failed to unmarshal encrypted auth: %v", err)
			return
		}

		if crypto.HashPSK(psk) != authBody.PSK {
			log.Printf("Authentication failed for %s:%s - PSK hash mismatch", clientIP, hostname)
			debugLogger.Printf("Authentication failed for %s:%s - expected PSK hash: %s, got: %s", clientIP, hostname, crypto.HashPSK(psk), authBody.PSK)
			return
		}

		log.Printf("Authentication successful for %s:%s", clientIP, hostname)
		debugLogger.Printf("Authentication successful for %s:%s", clientIP, hostname)

		session = &Session{
			ClientAddr: clientAddr,
			Hostname:   hostname,
			Conn:       conn,
			Reader:     reader,
			Writer:     writer,
			PSK:        psk,
			TTYClients: make(map[net.Conn]bool),
		}
	} else {
		log.Printf("Invalid initial message: %s", msg.Method)
		return
	}

	msg, err = s.receiveMessageWithDecryption(reader, session.PSK)
	if err != nil || msg.Method != "start" {
		log.Printf("Failed to receive start message: %v", err)
		return
	}

	var startBody protocol.StartBody
	if err := msg.UnmarshalBody(&startBody); err == nil && startBody.Hostname != "" {
		session.Hostname = startBody.Hostname
	}

	sessionID := atomic.AddInt64(&s.nextID, 1)
	session.ID = sessionID
	session.LastPing = time.Now()

	s.sessionMu.Lock()
	s.sessions[sessionID] = session
	s.sessionMu.Unlock()

	confirmMsg, _ := protocol.NewMessage(0, "start:confirm", protocol.StartConfirmBody{
		SessionID: sessionID,
	})
	if err := s.sendMessage(session, confirmMsg); err != nil {
		log.Printf("Failed to send start confirmation: %v", err)
		return
	}

	ttyStartMsg, _ := protocol.NewMessage(sessionID, "tty:start", nil)
	if err := s.sendMessage(session, ttyStartMsg); err != nil {
		log.Printf("Failed to send tty:start: %v", err)
		return
	}

	log.Printf("Shit client connected! Session %d started for %s (%s)", sessionID, clientAddr, session.Hostname)
	debugLogger.Printf("Session established: ID=%d, Address=%s, Hostname=%s, PSK_Hash=%s", sessionID, clientAddr, session.Hostname, crypto.HashPSK(session.PSK)[:8]+"...")

	defer func() {
		s.sessionMu.Lock()
		delete(s.sessions, sessionID)
		s.sessionMu.Unlock()
		log.Printf("Shit client disconnected! Session %d ended for %s (%s)", sessionID, clientAddr, session.Hostname)
		debugLogger.Printf("Session terminated: ID=%d, Address=%s, Hostname=%s", sessionID, clientAddr, session.Hostname)
	}()

	for {
		msg, err := s.receiveMessageWithDecryption(reader, session.PSK)
		if err != nil {
			if err == io.EOF {
				log.Printf("Client %s disconnected", clientAddr)
			} else {
				log.Printf("Read error from %s: %v", clientAddr, err)
			}
			break
		}

		switch msg.Method {
		case "ping":
			session.LastPing = time.Now()
			pongMsg, _ := protocol.NewMessage(msg.ID, "pong", nil)
			if err := s.sendMessage(session, pongMsg); err != nil {
				debugLogger.Printf("Failed to send pong to session %d: %v", session.ID, err)
				return
			}

		case "tty:data":
			s.forwardTTYData(session, msg)
		}
	}
}

func (s *Server) handleKeyExchange(clientIP string, msg *protocol.Message, writer *bufio.Writer) (string, string, error) {
	var req protocol.KeyExchangeRequest
	if err := msg.UnmarshalBody(&req); err != nil {
		return "", "", err
	}

	keyID := fmt.Sprintf("%s:%s", clientIP, req.Hostname)

	psk, exists := s.pskManager.GetKey(keyID)
	if !exists {
		var err error
		psk, err = crypto.GeneratePSK()
		if err != nil {
			return "", "", err
		}

		if err := s.pskManager.SetKey(keyID, psk); err != nil {
			return "", "", err
		}

		log.Printf("Generated new PSK for %s", keyID)
	}

	resp, _ := protocol.NewMessage(0, "key:exchange:response", protocol.KeyExchangeResponse{
		PSK: psk,
	})

	data, _ := resp.Marshal()
	writer.Write(data)
	writer.WriteString("\n")
	writer.Flush()

	return psk, req.Hostname, nil
}

func (s *Server) handleSocketConnection(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			break
		}

		var req map[string]interface{}
		if err := json.Unmarshal(bytes.TrimSpace(line), &req); err != nil {
			continue
		}

		method, _ := req["method"].(string)

		switch method {
		case "list":
			s.handleListSessions(writer)

		case "connect":
			sessionID, _ := req["sessionId"].(float64)
			s.handleTTYConnect(int64(sessionID), conn, writer)
			return
		}
	}
}

func (s *Server) handleListSessions(writer *bufio.Writer) {
	s.sessionMu.RLock()
	defer s.sessionMu.RUnlock()

	sessions := make([]map[string]interface{}, 0)
	for id, session := range s.sessions {
		sessions = append(sessions, map[string]interface{}{
			"id":       id,
			"address":  session.ClientAddr,
			"hostname": session.Hostname,
			"lastPing": session.LastPing.Unix(),
		})
	}

	resp, _ := json.Marshal(map[string]interface{}{
		"sessions": sessions,
	})

	writer.Write(resp)
	writer.WriteString("\n")
	writer.Flush()
}

func (s *Server) sendMessage(session *Session, msg *protocol.Message) error {
	data, err := msg.Marshal()
	if err != nil {
		return err
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	var finalData []byte
	if session.PSK != "" {
		if !strings.Contains(string(data), `"method":"pong"`) && !strings.Contains(string(data), `"method":"ping"`) {
			debugLogger.Printf("Session %d - Sending packet (before encryption): %s", session.ID, string(data))
		}
		encryptedData, err := crypto.EncryptMessage(session.PSK, data)
		if err != nil {
			return fmt.Errorf("encryption failed: %w", err)
		}
		finalData = encryptedData
		if !strings.Contains(string(data), `"method":"pong"`) && !strings.Contains(string(data), `"method":"ping"`) {
			debugLogger.Printf("Session %d - Sending encrypted packet: %s", session.ID, string(finalData))
		}
	} else {
		finalData = data
		debugLogger.Printf("Session %d - Sending packet (plain): %s", session.ID, string(finalData))
	}

	if _, err := session.Writer.Write(finalData); err != nil {
		return err
	}
	if _, err := session.Writer.WriteString("\n"); err != nil {
		return err
	}
	return session.Writer.Flush()
}

func (s *Server) receiveMessage(reader *bufio.Reader) (*protocol.Message, error) {
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return nil, err
	}

	line = bytes.TrimSpace(line)

	debugLogger.Printf("Received packet: %s", string(line))

	return protocol.UnmarshalMessage(line)
}

// receiveMessageWithDecryption receives and decrypts a message using session PSK
func (s *Server) receiveMessageWithDecryption(reader *bufio.Reader, psk string) (*protocol.Message, error) {
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return nil, err
	}

	line = bytes.TrimSpace(line)

	debugLogger.Printf("Received encrypted packet: %s", string(line))

	var messageData []byte
	if psk != "" {
		decryptedData, err := crypto.DecryptMessage(psk, line)
		if err != nil {
			debugLogger.Printf("Failed to decrypt message: %v", err)
			return nil, fmt.Errorf("failed to decrypt message: %w", err)
		} else {
			messageData = decryptedData
			if !strings.Contains(string(messageData), `"method":"ping"`) && !strings.Contains(string(messageData), `"method":"pong"`) {
				debugLogger.Printf("Decrypted packet: %s", string(messageData))
			}
		}
	} else {
		messageData = line
		debugLogger.Printf("Processing plain text packet: %s", string(messageData))
	}

	return protocol.UnmarshalMessage(messageData)
}

func (s *Server) cleanupSessions() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		s.sessionMu.Lock()
		for id, session := range s.sessions {
			timeSinceLastPing := time.Since(session.LastPing)
			if timeSinceLastPing > 30*time.Second {
				debugLogger.Printf("Session %d timed out (last ping: %v ago)", id, timeSinceLastPing)
				session.Conn.Close()
				delete(s.sessions, id)
				log.Printf("Session %d timed out", id)
			}
		}
		s.sessionMu.Unlock()
	}
}

func (s *Server) forwardTTYData(session *Session, msg *protocol.Message) {
	session.mu.Lock()
	defer session.mu.Unlock()

	for client := range session.TTYClients {
		if client != nil {
			data, err := msg.Marshal()
			if err != nil {
				debugLogger.Printf("Failed to marshal TTY data: %v", err)
				continue
			}

			if _, err := client.Write(data); err != nil {
				debugLogger.Printf("Failed to write TTY data to client: %v", err)
				delete(session.TTYClients, client)
				client.Close()
			} else {
				client.Write([]byte("\n"))
			}
		}
	}
}

func (s *Server) handleTTYConnect(sessionID int64, conn net.Conn, writer *bufio.Writer) {
	// Find the session
	s.sessionMu.RLock()
	session, exists := s.sessions[sessionID]
	s.sessionMu.RUnlock()

	if !exists {
		resp := map[string]interface{}{
			"success": false,
			"error":   "Session not found",
		}
		data, _ := json.Marshal(resp)
		writer.Write(data)
		writer.WriteString("\n")
		writer.Flush()
		return
	}

	session.mu.Lock()
	session.TTYClients[conn] = true
	session.mu.Unlock()
	resp := map[string]interface{}{
		"success": true,
		"message": "Connected to TTY session",
	}
	data, _ := json.Marshal(resp)
	writer.Write(data)
	writer.WriteString("\n")
	writer.Flush()

	log.Printf("Shit client connected to session %d", sessionID)

	ttyStartMsg, _ := protocol.NewMessage(sessionID, "tty:start", nil)
	if err := s.sendMessage(session, ttyStartMsg); err != nil {
		log.Printf("Failed to send tty:start to session %d: %v", sessionID, err)
	}
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			break
		}

		var inputMsg protocol.Message
		if err := json.Unmarshal(bytes.TrimSpace(line), &inputMsg); err != nil {
			continue
		}

		if inputMsg.Method == "tty:data" || inputMsg.Method == "tty:resize" {
			if err := s.sendMessage(session, &inputMsg); err != nil {
				debugLogger.Printf("Failed to forward TTY input: %v", err)
				break
			}
		}
	}

	session.mu.Lock()
	delete(session.TTYClients, conn)
	session.mu.Unlock()

	log.Printf("Shit client disconnected from session %d", sessionID)
}
