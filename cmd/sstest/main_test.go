package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestRunRejectsUnknownMode(t *testing.T) {
	t.Parallel()

	err := run(context.Background(), "unknown", zap.NewNop())
	if err == nil || !strings.Contains(err.Error(), "SSBAD_MODE") {
		t.Fatalf("run() error = %v", err)
	}
}

func TestRuntimeLogBoundsUseOnlyLevelAndMessage(t *testing.T) {
	t.Parallel()

	clock := &runtimeLogTestClock{now: time.Unix(1_700_000_000, 0)}
	core, observed := observer.New(zapcore.DebugLevel)
	logger := withRuntimeLogBounds(zap.New(core, zap.WithClock(clock)))

	const stormEntries = 100_000
	for i := 0; i < stormEntries; i++ {
		logger.Warn(
			"Failed to batch read packets from natConn",
			zap.Int("session", i),
			zap.Int("error-code", i),
			zap.Int("attempt", i),
		)
	}
	logger.With(zap.String("client", "dynamic-context")).Warn("Failed to batch read packets from natConn")
	if got := observed.FilterMessage("Failed to batch read packets from natConn").Len(); got != runtimeLogFirstPerKey {
		t.Fatalf("same level/message with changing fields emitted %d entries, want %d", got, runtimeLogFirstPerKey)
	}

	for i := 0; i < runtimeLogFirstPerKey; i++ {
		logger.Info("Failed to batch read packets from natConn", zap.Int("attempt", i))
		logger.Warn("a different failure", zap.Int("attempt", i))
	}
	if got := observed.FilterLevelExact(zapcore.InfoLevel).FilterMessage("Failed to batch read packets from natConn").Len(); got != runtimeLogFirstPerKey {
		t.Fatalf("different level emitted %d entries, want %d", got, runtimeLogFirstPerKey)
	}
	if got := observed.FilterLevelExact(zapcore.WarnLevel).FilterMessage("a different failure").Len(); got != runtimeLogFirstPerKey {
		t.Fatalf("different message emitted %d entries, want %d", got, runtimeLogFirstPerKey)
	}
}

func TestRuntimeLogBoundsResetAfterWindow(t *testing.T) {
	t.Parallel()

	clock := &runtimeLogTestClock{now: time.Unix(1_700_000_000, 0)}
	core, observed := observer.New(zapcore.DebugLevel)
	logger := withRuntimeLogBounds(zap.New(core, zap.WithClock(clock)))

	for i := 0; i < runtimeLogFirstPerKey+1; i++ {
		logger.Warn("repeating failure")
	}
	clock.now = clock.now.Add(runtimeLogSamplingWindow)
	for i := 0; i < runtimeLogFirstPerKey+1; i++ {
		logger.Warn("repeating failure")
	}

	if got, want := observed.Len(), 2*runtimeLogFirstPerKey; got != want {
		t.Fatalf("entries across two sampling windows = %d, want %d", got, want)
	}
}

func TestRuntimeLogStormEncodedOutputIsBounded(t *testing.T) {
	t.Parallel()

	clock := &runtimeLogTestClock{now: time.Unix(1_700_000_000, 0)}
	var output bytes.Buffer
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(&output),
		zapcore.DebugLevel,
	)
	logger := withRuntimeLogBounds(zap.New(core, zap.WithClock(clock)))

	const stormEntries = 1_000_000
	for i := 0; i < stormEntries; i++ {
		logger.Warn(
			"Failed to batch read packets from natConn",
			zap.Int("session", i),
			zap.Int("error-code", i),
			zap.Int("attempt", i),
		)
	}
	if err := logger.Sync(); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}

	lines := bytes.Count(output.Bytes(), []byte{'\n'})
	encodedBytes := output.Len()
	t.Logf("encoded %d-entry storm as %d lines and %d bytes", stormEntries, lines, encodedBytes)
	if lines != runtimeLogFirstPerKey {
		t.Fatalf("encoded lines from %d-entry storm = %d, want %d", stormEntries, lines, runtimeLogFirstPerKey)
	}
	if limit := 64 << 10; encodedBytes >= limit {
		t.Fatalf("encoded bytes from %d-entry storm = %d, want less than %d", stormEntries, encodedBytes, limit)
	}
}

type runtimeLogTestClock struct {
	now time.Time
}

func (clock *runtimeLogTestClock) Now() time.Time {
	return clock.now
}

func (*runtimeLogTestClock) NewTicker(duration time.Duration) *time.Ticker {
	return time.NewTicker(duration)
}
