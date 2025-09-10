package main

import (
	"fmt"
	"log"

	"shit/internal/apps/shit"
	"shit/internal/config"
)

func main() {
	cfg := config.GetShitCLIConfig()
	cli := shit.NewCLI(cfg)

	fmt.Println("SHIT - Shell Interface Terminal")
	fmt.Println("================================")

	if err := cli.Run(); err != nil {
		log.Fatalf("CLI error: %v", err)
	}
}
