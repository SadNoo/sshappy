package main

import (
	"context"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func TestRunRejectsUnknownMode(t *testing.T) {
	t.Parallel()

	err := run(context.Background(), "unknown", zap.NewNop())
	if err == nil || !strings.Contains(err.Error(), "SSBAD_MODE") {
		t.Fatalf("run() error = %v", err)
	}
}
