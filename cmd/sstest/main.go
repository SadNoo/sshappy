package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/database64128/shadowsocks-go/internal/flyskynode"
	"github.com/database64128/shadowsocks-go/logging"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	runtimeLogSamplingWindow = time.Minute
	runtimeLogFirstPerKey    = 10
)

func main() {
	logger, err := logging.NewZapLogger("console-nocolor", zapcore.InfoLevel)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	logger = withRuntimeLogBounds(logger)
	defer logger.Sync()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, strings.ToLower(strings.TrimSpace(os.Getenv("SSBAD_MODE"))), logger); err != nil {
		logger.Error("sshappy stopped", zap.Error(err))
		os.Exit(1)
	}
}

// withRuntimeLogBounds limits each distinct level-and-message pair to a fixed
// number of entries per window. Zap's sampler deliberately excludes structured
// fields from its key, so changing addresses, usernames, session IDs, or error
// values cannot bypass the bound. Thereafter is zero to keep a tight error loop
// from retaining a volume-dependent fraction of its output.
func withRuntimeLogBounds(logger *zap.Logger) *zap.Logger {
	return logger.WithOptions(zap.WrapCore(func(core zapcore.Core) zapcore.Core {
		return zapcore.NewSamplerWithOptions(
			core,
			runtimeLogSamplingWindow,
			runtimeLogFirstPerKey,
			0,
		)
	}))
}

func run(ctx context.Context, mode string, logger *zap.Logger) error {
	switch mode {
	case "", "flysky":
		return flyskynode.Run(ctx, flyskynode.LoadConfig(), logger)
	default:
		return fmt.Errorf("unsupported SSBAD_MODE %q; the Flysky build only accepts flysky", mode)
	}
}
