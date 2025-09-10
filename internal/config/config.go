package config

import (
	"os"
	"strings"
)

type ShitConfig struct {
	ServerAddr string
	ServerPort int
	KeysFile   string
	Debug      bool
}

type ShitServerConfig struct {
	ListenAddr     string
	ListenPort     int
	SocketPath     string
	AuthorizedKeys string
	Debug          bool
}

type ShitCLIConfig struct {
	SocketPath string
}

func GetShitConfig() *ShitConfig {
	serverAddr := os.Getenv("SHIT_MAN_ADDR")
	if serverAddr == "" {
		serverAddr = "127.0.0.1"
	}

	keysFile := os.Getenv("SHIT_KEYS_FILE")
	if keysFile == "" {
		keysFile = ".keys"
	}

	debug := strings.ToLower(os.Getenv("SHIT_DEBUG")) == "true"

	return &ShitConfig{
		ServerAddr: serverAddr,
		ServerPort: 5422,
		KeysFile:   keysFile,
		Debug:      debug,
	}
}

func GetShitServerConfig() *ShitServerConfig {
	listenAddr := os.Getenv("SHIT_MAN_LISTEN_AT")
	if listenAddr == "" {
		listenAddr = "0.0.0.0"
	}

	socketPath := os.Getenv("SHIT_SOCKET_PATH")
	if socketPath == "" {
		socketPath = "/var/run/shit-man.sock"
	}

	authKeys := os.Getenv("SHIT_AUTHORIZED_KEYS")
	if authKeys == "" {
		authKeys = ".authorized_keys"
	}

	debug := strings.ToLower(os.Getenv("SHIT_SERVER_DEBUG")) == "true"

	return &ShitServerConfig{
		ListenAddr:     listenAddr,
		ListenPort:     5422,
		SocketPath:     socketPath,
		AuthorizedKeys: authKeys,
		Debug:          debug,
	}
}

func GetShitCLIConfig() *ShitCLIConfig {
	socketPath := os.Getenv("SHIT_SOCKET_PATH")
	if socketPath == "" {
		socketPath = "/var/run/shit-man.sock"
	}

	return &ShitCLIConfig{
		SocketPath: socketPath,
	}
}
