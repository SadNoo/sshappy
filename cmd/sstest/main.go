package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/database64128/shadowsocks-go/internal/panel"
	"github.com/database64128/shadowsocks-go/logging"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	version   = "4.4.0-dev"
	commit    = "unknown"
	buildTime = "unknown"
)

func main() {
	os.Exit(run())
}

func run() int {
	logger, err := logging.NewZapLogger("console-nocolor", zapcore.InfoLevel)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = logger.Sync() }()
	logger.Info("sshappy build",
		zap.String("version", version),
		zap.String("commit", commit),
		zap.String("buildTime", buildTime),
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := panel.Run(ctx, panel.LoadConfig(), logger); err != nil {
		logger.Error("sshappy stopped", zap.Error(err))
		return 1
	}
	return 0
}
