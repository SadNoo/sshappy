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

func main() {
	logger, err := logging.NewZapLogger("console-nocolor", zapcore.InfoLevel)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer logger.Sync()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := panel.Run(ctx, panel.LoadConfig(), logger); err != nil {
		logger.Error("sshappy stopped", zap.Error(err))
		os.Exit(1)
	}
}
