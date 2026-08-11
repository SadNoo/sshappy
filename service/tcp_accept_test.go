package service

import (
	"context"
	_ "embed"
	"errors"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

//go:embed tcp.go
var tcpRelaySource string

type tcpAcceptResult struct {
	connection *net.TCPConn
	err        error
}

type scriptedTCPAcceptor struct {
	results  []tcpAcceptResult
	fallback error
	calls    atomic.Int64
}

func (acceptor *scriptedTCPAcceptor) AcceptTCP() (*net.TCPConn, error) {
	call := int(acceptor.calls.Add(1)) - 1
	if call < len(acceptor.results) {
		result := acceptor.results[call]
		return result.connection, result.err
	}
	return nil, acceptor.fallback
}

type repeatedTCPAcceptError struct {
	err       error
	remaining int
	calls     atomic.Int64
}

func (acceptor *repeatedTCPAcceptError) AcceptTCP() (*net.TCPConn, error) {
	acceptor.calls.Add(1)
	if acceptor.remaining > 0 {
		acceptor.remaining--
		return nil, acceptor.err
	}
	return new(net.TCPConn), nil
}

type temporaryTCPAcceptError struct{}

func (temporaryTCPAcceptError) Error() string   { return "temporary TCP accept failure" }
func (temporaryTCPAcceptError) Timeout() bool   { return false }
func (temporaryTCPAcceptError) Temporary() bool { return true }

type timeoutTCPAcceptError struct{}

func (timeoutTCPAcceptError) Error() string   { return "TCP accept timeout" }
func (timeoutTCPAcceptError) Timeout() bool   { return true }
func (timeoutTCPAcceptError) Temporary() bool { return true }

var errPermanentTCPAccept = errors.New("permanent TCP accept failure")

func TestTCPAcceptLoopActualClosedListenerExitsWithoutLogging(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("socket bind unavailable in this sandbox: %v", err)
		}
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	var reports atomic.Int64
	if err := runTCPAcceptLoop(context.Background(), listener, func(error) {
		reports.Add(1)
	}, func(*net.TCPConn) {
		t.Fatal("closed listener accepted a connection")
	}); err != nil {
		t.Fatalf("closed listener returned %v, want a normal exit", err)
	}
	if got := reports.Load(); got != 0 {
		t.Fatalf("closed listener logged %d failures, want 0", got)
	}
}

func TestTCPAcceptLoopExpiredDeadlineExitsWithoutLogging(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("socket bind unavailable in this sandbox: %v", err)
		}
		t.Fatal(err)
	}
	defer listener.Close()
	if err := listener.SetDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}

	var reports atomic.Int64
	if err := runTCPAcceptLoop(context.Background(), listener, func(error) {
		reports.Add(1)
	}, func(*net.TCPConn) {
		t.Fatal("expired listener accepted a connection")
	}); err != nil {
		t.Fatalf("expired listener returned %v, want a normal exit", err)
	}
	if got := reports.Load(); got != 0 {
		t.Fatalf("expired listener logged %d failures, want 0", got)
	}
}

func TestTCPAcceptLoopPermanentFailureStopsAtFirstOfHundredThousand(t *testing.T) {
	acceptor := &repeatedTCPAcceptError{err: errPermanentTCPAccept, remaining: 100_000}
	var reports atomic.Int64

	started := time.Now()
	err := runTCPAcceptLoop(context.Background(), acceptor, func(error) {
		reports.Add(1)
	}, func(*net.TCPConn) {
		t.Fatal("permanent failure accepted a connection")
	})
	if !errors.Is(err, errPermanentTCPAccept) {
		t.Fatalf("permanent accept error = %v, want %v", err, errPermanentTCPAccept)
	}
	if got := acceptor.calls.Load(); got != 1 {
		t.Fatalf("permanent acceptor called %d times, want 1 of 100000 possible failures", got)
	}
	if got := reports.Load(); got != 1 {
		t.Fatalf("permanent failure logged %d times, want 1", got)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("permanent failure took %s to terminate", elapsed)
	}
}

func TestTCPAcceptLoopTimeoutExitsWithoutLogging(t *testing.T) {
	acceptor := &repeatedTCPAcceptError{err: timeoutTCPAcceptError{}, remaining: 100_000}
	var reports atomic.Int64
	if err := runTCPAcceptLoop(context.Background(), acceptor, func(error) {
		reports.Add(1)
	}, func(*net.TCPConn) {
		t.Fatal("timeout accepted a connection")
	}); err != nil {
		t.Fatalf("timeout returned %v, want a normal exit", err)
	}
	if got := acceptor.calls.Load(); got != 1 {
		t.Fatalf("timeout acceptor called %d times, want 1", got)
	}
	if got := reports.Load(); got != 0 {
		t.Fatalf("timeout logged %d failures, want 0", got)
	}
}

func TestTCPAcceptLoopTemporaryFailureIsBoundedAndCancelable(t *testing.T) {
	acceptor := &repeatedTCPAcceptError{err: temporaryTCPAcceptError{}, remaining: 100_000}
	var reports atomic.Int64
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()

	started := time.Now()
	err := runTCPAcceptLoop(ctx, acceptor, func(error) {
		reports.Add(1)
	}, func(*net.TCPConn) {
		t.Fatal("temporary failure accepted a connection")
	})
	elapsed := time.Since(started)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("temporary accept loop error = %v, want context deadline", err)
	}
	if got := acceptor.calls.Load(); got < 2 || got > 5 {
		t.Fatalf("temporary acceptor called %d times in %s, want bounded exponential retries", got, elapsed)
	}
	if got := reports.Load(); got != 1 {
		t.Fatalf("continuous temporary failure logged %d times, want 1", got)
	}
	if elapsed < 50*time.Millisecond || elapsed > time.Second {
		t.Fatalf("temporary failure duration = %s, want cancellation-aware backoff", elapsed)
	}
}

func TestTCPAcceptLoopDispatchesConnectionAndResetsFailureIncident(t *testing.T) {
	acceptor := &scriptedTCPAcceptor{results: []tcpAcceptResult{
		{err: temporaryTCPAcceptError{}},
		{connection: new(net.TCPConn)},
		{err: temporaryTCPAcceptError{}},
		{err: errPermanentTCPAccept},
	}}
	var reports, handled atomic.Int64

	err := runTCPAcceptLoop(context.Background(), acceptor, func(error) {
		reports.Add(1)
	}, func(*net.TCPConn) {
		handled.Add(1)
	})
	if !errors.Is(err, errPermanentTCPAccept) {
		t.Fatalf("accept loop error = %v, want %v", err, errPermanentTCPAccept)
	}
	if got := handled.Load(); got != 1 {
		t.Fatalf("accepted connections dispatched = %d, want 1", got)
	}
	if got := acceptor.calls.Load(); got != 4 {
		t.Fatalf("acceptor calls = %d, want 4", got)
	}
	if got := reports.Load(); got != 2 {
		t.Fatalf("failure incidents logged = %d, want 2", got)
	}
}

func TestTCPRelayStartUsesBoundedAcceptLoop(t *testing.T) {
	if calls := strings.Count(tcpRelaySource, ".AcceptTCP()"); calls != 1 {
		t.Fatalf("tcp.go contains %d direct AcceptTCP calls, want only the bounded helper", calls)
	}
	if !strings.Contains(tcpRelaySource, "runTCPAcceptLoop(ctx, lnc.listener") {
		t.Fatal("TCPRelay.Start does not route listener accepts through runTCPAcceptLoop")
	}
	if strings.Contains(tcpRelaySource, "_ = runTCPAcceptLoop") {
		t.Fatal("TCPRelay.Start discards the accept loop result")
	}
	if !strings.Contains(tcpRelaySource, `s.reportListenerRuntimeFailure(ctx, "TCP", index, lnc.address, err)`) {
		t.Fatal("TCPRelay.Start does not report asynchronous accept loop failures")
	}
}

func TestTCPRelayReportsPermanentAcceptFailure(t *testing.T) {
	relay := &TCPRelay{runtimeFailureReporter: newRuntimeFailureReporter()}
	relay.reportListenerRuntimeFailure(context.Background(), "TCP", 2, "127.0.0.1:2343", errPermanentTCPAccept)

	select {
	case err := <-relay.runtimeFailures():
		if !errors.Is(err, errPermanentTCPAccept) {
			t.Fatalf("reported error = %v, want wrapped %v", err, errPermanentTCPAccept)
		}
		if !strings.Contains(err.Error(), "listener 2") || !strings.Contains(err.Error(), "127.0.0.1:2343") {
			t.Fatalf("reported error lacks listener context: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("permanent accept failure was not reported")
	}
}

func TestTCPRelayIgnoresAcceptResultDuringShutdown(t *testing.T) {
	relay := &TCPRelay{runtimeFailureReporter: newRuntimeFailureReporter()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	relay.reportListenerRuntimeFailure(ctx, "TCP", 0, "127.0.0.1:2343", context.Canceled)

	select {
	case err := <-relay.runtimeFailures():
		t.Fatalf("shutdown result was reported as a runtime failure: %v", err)
	default:
	}
}
