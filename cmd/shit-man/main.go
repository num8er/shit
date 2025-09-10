package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	shitman "shit/internal/apps/shit-man"
	"shit/internal/config"
)

func main() {
	cfg := config.GetShitServerConfig()
	server := shitman.NewServer(cfg)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down shit-man server...")
		os.Exit(0)
	}()

	log.Printf("Starting shit-man server on port %d, socket at %s", cfg.ListenPort, cfg.SocketPath)
	if err := server.Run(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
