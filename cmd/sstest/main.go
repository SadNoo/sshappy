package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/database64128/shadowsocks-go/internal/flyskynode"
	"github.com/database64128/shadowsocks-go/logging"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func main() {
	logger, err := logging.NewZapLogger("console-nocolor", zapcore.InfoLevel)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer logger.Sync()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, strings.ToLower(strings.TrimSpace(os.Getenv("SSBAD_MODE"))), logger); err != nil {
		logger.Error("sshappy stopped", zap.Error(err))
		os.Exit(1)
	}
}

func run(ctx context.Context, mode string, logger *zap.Logger) error {
	switch mode {
	case "", "flysky":
		return flyskynode.Run(ctx, flyskynode.LoadConfig(), logger)
	default:
		return fmt.Errorf("unsupported SSBAD_MODE %q; the Flysky build only accepts flysky", mode)
	}
}
