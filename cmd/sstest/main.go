package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/SadNoo/sshappy/internal/sstest"
)

func main() {
	cfg := sstest.LoadConfig()
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := sstest.Run(ctx, cfg); err != nil {
		log.Printf("fatal: %v", err)
		os.Exit(1)
	}
}
