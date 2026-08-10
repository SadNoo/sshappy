package service

import (
	"context"
	"errors"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

type temporaryUDPReadError struct{}

func (temporaryUDPReadError) Error() string   { return "temporary UDP read failure" }
func (temporaryUDPReadError) Timeout() bool   { return false }
func (temporaryUDPReadError) Temporary() bool { return true }

type permanentUDPReadError struct{}

func (permanentUDPReadError) Error() string   { return "permanent UDP read failure" }
func (permanentUDPReadError) Timeout() bool   { return false }
func (permanentUDPReadError) Temporary() bool { return false }

type timeoutUDPReadError struct{}

func (timeoutUDPReadError) Error() string   { return "UDP read timeout" }
func (timeoutUDPReadError) Timeout() bool   { return true }
func (timeoutUDPReadError) Temporary() bool { return true }

func TestUDPReadErrorBackoffActualClosedSocketTerminatesWithoutLogging(t *testing.T) {
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("socket bind unavailable in this sandbox: %v", err)
		}
		t.Fatal(err)
	}
	if err := udpConn.Close(); err != nil {
		t.Fatal(err)
	}
	_, _, _, _, readErr := udpConn.ReadMsgUDPAddrPort(make([]byte, 64), nil)
	if !errors.Is(readErr, net.ErrClosed) {
		t.Fatalf("closed UDP socket read error = %v, want net.ErrClosed", readErr)
	}

	var backoff udpReadErrorBackoff
	var logCalls atomic.Int64
	if backoff.shouldRetry(context.Background(), readErr, func(error) { logCalls.Add(1) }) {
		t.Fatal("closed UDP socket was treated as retryable")
	}
	if calls := logCalls.Load(); calls != 0 {
		t.Fatalf("closed UDP socket logged %d times, want 0", calls)
	}
}

func TestUDPReadErrorBackoffPermanentFailureStopsAtFirstOfHundredThousand(t *testing.T) {
	var backoff udpReadErrorBackoff
	var attempts, logCalls atomic.Int64
	for range 100_000 {
		attempts.Add(1)
		if !backoff.shouldRetry(context.Background(), permanentUDPReadError{}, func(error) { logCalls.Add(1) }) {
			break
		}
	}
	if attempts.Load() != 1 {
		t.Fatalf("permanent error attempted %d times, want exactly 1", attempts.Load())
	}
	if logCalls.Load() != 1 {
		t.Fatalf("permanent error logged %d times, want exactly 1", logCalls.Load())
	}
}

func TestUDPReadErrorBackoffTimeoutTerminatesWithoutLogging(t *testing.T) {
	var backoff udpReadErrorBackoff
	var logCalls atomic.Int64
	if backoff.shouldRetry(context.Background(), timeoutUDPReadError{}, func(error) { logCalls.Add(1) }) {
		t.Fatal("UDP timeout was treated as retryable")
	}
	if calls := logCalls.Load(); calls != 0 {
		t.Fatalf("UDP timeout logged %d times, want 0", calls)
	}
}

func TestUDPReadErrorBackoffPersistentTemporaryFailureIsBoundedAndCancelable(t *testing.T) {
	var backoff udpReadErrorBackoff
	var attempts, logCalls atomic.Int64
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()

	started := time.Now()
	for range 100_000 {
		attempts.Add(1)
		if !backoff.shouldRetry(ctx, temporaryUDPReadError{}, func(error) { logCalls.Add(1) }) {
			break
		}
	}
	elapsed := time.Since(started)
	if calls := attempts.Load(); calls < 2 || calls > 5 {
		t.Fatalf("temporary error attempted %d times in %s, want bounded exponential retries", calls, elapsed)
	}
	if calls := logCalls.Load(); calls != 1 {
		t.Fatalf("persistent temporary error logged %d times, want exactly 1", calls)
	}
	if elapsed < 50*time.Millisecond || elapsed > time.Second {
		t.Fatalf("temporary error retry duration = %s, want cancellation-aware backoff", elapsed)
	}
}

func TestUDPReadErrorBackoffSuccessResetsSamplingAndDelay(t *testing.T) {
	var backoff udpReadErrorBackoff
	var logCalls atomic.Int64
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if !backoff.shouldRetry(ctx, temporaryUDPReadError{}, func(error) { logCalls.Add(1) }) {
		t.Fatal("temporary error was not retried")
	}
	backoff.reset()
	if !backoff.shouldRetry(ctx, temporaryUDPReadError{}, func(error) { logCalls.Add(1) }) {
		t.Fatal("temporary error after success was not retried")
	}
	if calls := logCalls.Load(); calls != 2 {
		t.Fatalf("two separate temporary failure incidents logged %d times, want 2", calls)
	}
}
