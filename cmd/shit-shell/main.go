package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"shit/internal/apps/shit-shell"
	"shit/internal/config"
)

func main() {
	cfg := config.GetShitConfig()
	client := shitshell.NewClient(cfg)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down shit-shell client...")
		os.Exit(0)
	}()

	log.Printf("Starting shit-shell client, connecting to %s:%d", cfg.ServerAddr, cfg.ServerPort)
	if err := client.Run(); err != nil {
		log.Fatalf("Client error: %v", err)
	}
}
