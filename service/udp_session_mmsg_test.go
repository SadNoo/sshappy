//go:build linux || netbsd

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

	"github.com/database64128/shadowsocks-go/conn"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

//go:embed udp_session.go
var udpSessionSource string

//go:embed udp_nat.go
var udpNATSource string

//go:embed udp_session_mmsg.go
var udpSessionMmsgSource string

//go:embed udp_nat_mmsg.go
var udpNATMmsgSource string

//go:embed udp_transparent_linux.go
var udpTransparentLinuxSource string

var udpRelaySources = map[string]string{
	"udp_session.go":           udpSessionSource,
	"udp_nat.go":               udpNATSource,
	"udp_session_mmsg.go":      udpSessionMmsgSource,
	"udp_nat_mmsg.go":          udpNATMmsgSource,
	"udp_transparent_linux.go": udpTransparentLinuxSource,
}

type repeatedMmsgReadError struct {
	err       error
	remaining int
	calls     atomic.Int64
}

func (reader *repeatedMmsgReadError) ReadMsgs([]conn.Mmsghdr, int) (int, error) {
	reader.calls.Add(1)
	if reader.remaining > 0 {
		reader.remaining--
		return 0, reader.err
	}
	return 1, nil
}

type temporaryMmsgReadError struct{}

func (temporaryMmsgReadError) Error() string   { return "temporary mmsg read failure" }
func (temporaryMmsgReadError) Timeout() bool   { return false }
func (temporaryMmsgReadError) Temporary() bool { return true }

type permanentMmsgReadError struct{}

func (permanentMmsgReadError) Error() string   { return "permanent mmsg read failure" }
func (permanentMmsgReadError) Timeout() bool   { return false }
func (permanentMmsgReadError) Temporary() bool { return false }

func TestReadMmsgBatchHundredThousandClosedErrorsExitOnce(t *testing.T) {
	reader := &repeatedMmsgReadError{err: net.ErrClosed, remaining: 100_000}
	var logCalls atomic.Int64

	started := time.Now()
	_, err := readMmsgBatch(context.Background(), reader, make([]conn.Mmsghdr, 1), func(error) {
		logCalls.Add(1)
	})
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("readMmsgBatch() error = %v, want net.ErrClosed", err)
	}
	if calls := reader.calls.Load(); calls != 1 {
		t.Fatalf("closed reader called %d times, want exactly 1", calls)
	}
	if calls := logCalls.Load(); calls != 0 {
		t.Fatalf("expected closed socket logged %d times, want 0", calls)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("closed reader took %s to exit", elapsed)
	}
}

func TestReadMmsgBatchActualClosedSocketExitsWithoutLogging(t *testing.T) {
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("socket bind unavailable in this sandbox: %v", err)
		}
		t.Fatal(err)
	}
	mmsgConn, err := conn.NewMmsgConn(udpConn)
	if err != nil {
		_ = udpConn.Close()
		t.Fatal(err)
	}
	reader := mmsgConn.NewRConn()
	if err := udpConn.Close(); err != nil {
		t.Fatal(err)
	}
	var logCalls atomic.Int64

	_, err = readMmsgBatch(context.Background(), reader, make([]conn.Mmsghdr, 1), func(error) {
		logCalls.Add(1)
	})
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed UDP socket error = %v, want net.ErrClosed", err)
	}
	if calls := logCalls.Load(); calls != 0 {
		t.Fatalf("actual closed socket logged %d times, want 0", calls)
	}
}

func TestReadMmsgBatchPermanentErrorLogsOnceAndExits(t *testing.T) {
	reader := &repeatedMmsgReadError{err: permanentMmsgReadError{}, remaining: 100_000}
	var logCalls atomic.Int64

	_, err := readMmsgBatch(context.Background(), reader, make([]conn.Mmsghdr, 1), func(error) {
		logCalls.Add(1)
	})
	if err == nil {
		t.Fatal("permanent read error was treated as success")
	}
	if calls := reader.calls.Load(); calls != 1 {
		t.Fatalf("permanent reader called %d times, want exactly 1", calls)
	}
	if calls := logCalls.Load(); calls != 1 {
		t.Fatalf("permanent read error logged %d times, want exactly 1", calls)
	}
}

func TestReadMmsgBatchTemporaryErrorsBackOffAndHonorCancellation(t *testing.T) {
	reader := &repeatedMmsgReadError{err: temporaryMmsgReadError{}, remaining: 100_000}
	var logCalls atomic.Int64
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()

	started := time.Now()
	_, err := readMmsgBatch(ctx, reader, make([]conn.Mmsghdr, 1), func(error) {
		logCalls.Add(1)
	})
	elapsed := time.Since(started)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("temporary read loop error = %v, want context deadline", err)
	}
	if calls := reader.calls.Load(); calls < 2 || calls > 5 {
		t.Fatalf("temporary reader called %d times in %s, want bounded exponential retries", calls, elapsed)
	}
	if calls := logCalls.Load(); calls != 1 {
		t.Fatalf("persistent temporary read error logged %d times, want exactly 1", calls)
	}
	if elapsed < 50*time.Millisecond || elapsed > time.Second {
		t.Fatalf("temporary read retry duration = %s, want cancellation-aware backoff", elapsed)
	}
}

func TestAllMmsgNatConnReadLoopsUseBoundedHelper(t *testing.T) {
	tests := []struct {
		path              string
		minimumHelperUses int
	}{
		{path: "udp_session_mmsg.go", minimumHelperUses: 3}, // definition + server + session downlink
		{path: "udp_nat_mmsg.go", minimumHelperUses: 2},
		{path: "udp_transparent_linux.go", minimumHelperUses: 2},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			text := udpRelaySources[test.path]
			if uses := strings.Count(text, "readMmsgBatch("); uses < test.minimumHelperUses {
				t.Fatalf("%s uses readMmsgBatch %d times, want at least %d", test.path, uses, test.minimumHelperUses)
			}
			directReads := strings.Count(text, ".ReadMsgs(")
			wantDirectReads := 0
			if test.path == "udp_session_mmsg.go" {
				wantDirectReads = 1 // the shared readMmsgBatch implementation itself
			}
			if directReads != wantDirectReads {
				t.Fatalf("%s contains %d direct ReadMsgs calls, want %d", test.path, directReads, wantDirectReads)
			}
		})
	}
}

func TestGenericUDPReadLoopsUseBoundedErrorHandling(t *testing.T) {
	for _, path := range []string{"udp_session.go", "udp_nat.go"} {
		t.Run(path, func(t *testing.T) {
			text := udpRelaySources[path]
			if reads := strings.Count(text, ".ReadMsgUDPAddrPort("); reads != 2 {
				t.Fatalf("%s has %d UDP socket read loops, want 2", path, reads)
			}
			if guards := strings.Count(text, "readFailures.shouldRetry("); guards != 2 {
				t.Fatalf("%s has %d bounded read guards, want 2", path, guards)
			}
			if resets := strings.Count(text, "readFailures.reset()"); resets != 2 {
				t.Fatalf("%s has %d successful-read resets, want 2", path, resets)
			}
		})
	}
}

func TestUDPSessionCompletionLogsStayBelowInfo(t *testing.T) {
	for _, path := range []string{"udp_session.go", "udp_session_mmsg.go"} {
		t.Run(path, func(t *testing.T) {
			text := udpRelaySources[path]
			for _, message := range []string{
				"Finished relay serverConn -> natConn",
				"Finished relay serverConn <- natConn",
			} {
				if !strings.Contains(text, `.Debug("`+message+`"`) {
					t.Fatalf("%s does not emit %q at Debug", path, message)
				}
				if strings.Contains(text, `.Info("`+message+`"`) {
					t.Fatalf("%s emits per-session %q at Info", path, message)
				}
			}
		})
	}

	core, observed := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)
	logger.Debug("Finished relay serverConn -> natConn")
	logger.Debug("Finished relay serverConn <- natConn")
	if observed.Len() != 0 {
		t.Fatalf("Info logger captured per-session Debug completion logs: %+v", observed.All())
	}
	logger.Info("UDP relay metrics")
	if observed.Len() != 1 {
		t.Fatalf("minute UDP metrics Info was not retained: %+v", observed.All())
	}
}
