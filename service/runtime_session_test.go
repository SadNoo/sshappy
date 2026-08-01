package service

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
)

type sessionControllerTestObserver struct {
	basicTargetTestObserver
	accepted bool
	called   bool
}

func (o *sessionControllerTestObserver) BeginSession(parent context.Context, network, username string, source netip.AddrPort, target conn.Addr) (context.Context, func(), bool) {
	o.called = network == "tcp" && username == "7" && source == netip.MustParseAddrPort("203.0.113.1:12345") && target.Port() == 1023
	if !o.accepted {
		return parent, nil, false
	}
	ctx, cancel := context.WithCancel(parent)
	return ctx, cancel, true
}

func TestBeginRuntimeSessionUsesOptionalController(t *testing.T) {
	observer := &sessionControllerTestObserver{accepted: true}
	ctx, end, accepted := beginRuntimeSession(
		t.Context(),
		observer,
		"tcp",
		"7",
		netip.MustParseAddrPort("203.0.113.1:12345"),
		conn.AddrFromIPAndPort(netip.MustParseAddr("203.0.113.2"), 1023),
	)
	if !accepted || !observer.called || end == nil || ctx == t.Context() {
		t.Fatalf("managed session = (accepted=%v, called=%v, end=%v)", accepted, observer.called, end != nil)
	}
	end()
	select {
	case <-ctx.Done():
	default:
		t.Fatal("session end did not cancel the managed context")
	}
}

func TestBeginRuntimeSessionPreservesCompatibility(t *testing.T) {
	parent := t.Context()
	ctx, end, accepted := beginRuntimeSession(
		parent,
		basicTargetTestObserver{},
		"tcp",
		"7",
		netip.MustParseAddrPort("203.0.113.1:12345"),
		conn.AddrFromIPAndPort(netip.MustParseAddr("203.0.113.2"), 1023),
	)
	if !accepted || end != nil || ctx != parent {
		t.Fatalf("basic observer session = (accepted=%v, end=%v, sameContext=%v)", accepted, end != nil, ctx == parent)
	}
}

func TestCloseTCPConnectionsOnSessionCancel(t *testing.T) {
	client, clientPeer := net.Pipe()
	remote, remotePeer := net.Pipe()
	defer clientPeer.Close()
	defer remotePeer.Close()

	ctx, cancel := context.WithCancel(t.Context())
	stopClient := closeTCPConnectionOnSessionCancel(ctx, client)
	stopRemote := closeTCPConnectionOnSessionCancel(ctx, remote)
	cancel()
	defer stopClient()
	defer stopRemote()

	for name, peer := range map[string]net.Conn{"client": clientPeer, "remote": remotePeer} {
		t.Run(name, func(t *testing.T) {
			if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				// net.Pipe may report the peer closure while setting a deadline.
				return
			}
			if _, err := peer.Read(make([]byte, 1)); err == nil {
				t.Fatal("peer remained open after session cancellation")
			}
		})
	}
}

func TestUDPSessionCancellationActivationOrders(t *testing.T) {
	t.Run("cancel before activation", func(t *testing.T) {
		entry := &session{}
		ctx, cancel := context.WithCancel(t.Context())
		stop := entry.watchRuntimeCancellation(ctx)
		defer stop()
		cancel()
		waitForRuntimeCancellation(t, entry)

		natConn := newRuntimeTestUDPConn()
		defer natConn.Close()
		if entry.activateNATConn(natConn) {
			t.Fatal("NAT activation succeeded after cancellation")
		}
	})

	t.Run("cancel after activation", func(t *testing.T) {
		entry := &session{}
		natConn := newRuntimeTestUDPConn()
		defer natConn.Close()
		if !entry.activateNATConn(natConn) {
			t.Fatal("NAT activation failed before cancellation")
		}

		ctx, cancel := context.WithCancel(t.Context())
		stop := entry.watchRuntimeCancellation(ctx)
		defer stop()
		cancel()
		waitForRuntimeCancellation(t, entry)
		if entry.state.Load() != natConn {
			t.Fatal("cancellation lost the active NAT socket state")
		}
	})
}

func TestActivateNATConnDoesNotOverwriteStopSentinel(t *testing.T) {
	entry := &session{}
	stopSentinel := newRuntimeTestUDPConn()
	entry.state.Store(stopSentinel)
	natConn := newRuntimeTestUDPConn()
	defer natConn.Close()

	if entry.activateNATConn(natConn) {
		t.Fatal("NAT activation succeeded after stop installed its sentinel")
	}
	if got := entry.state.Load(); got != stopSentinel {
		t.Fatalf("NAT activation replaced stop sentinel: got %p, want %p", got, stopSentinel)
	}
}

func TestShouldStopUDPSessionRead(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
		err  error
		want bool
	}{
		{name: "deadline", ctx: t.Context(), err: os.ErrDeadlineExceeded, want: true},
		{name: "closed socket", ctx: t.Context(), err: net.ErrClosed, want: true},
		{name: "retryable failure", ctx: t.Context(), err: errors.New("temporary read failure")},
	}
	canceledCtx, cancel := context.WithCancel(t.Context())
	cancel()
	tests = append(tests, struct {
		name string
		ctx  context.Context
		err  error
		want bool
	}{name: "canceled session", ctx: canceledCtx, err: errors.New("socket failure"), want: true})

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := shouldStopUDPSessionRead(test.ctx, test.err); got != test.want {
				t.Fatalf("shouldStopUDPSessionRead() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestUDPSessionCancellationActivationRace(t *testing.T) {
	for range 200 {
		entry := &session{}
		natConn := newRuntimeTestUDPConn()
		ctx, cancel := context.WithCancel(t.Context())
		stop := entry.watchRuntimeCancellation(ctx)
		start := make(chan struct{})
		activated := make(chan bool, 1)
		go func() {
			<-start
			activated <- entry.activateNATConn(natConn)
		}()
		go func() {
			<-start
			cancel()
		}()
		close(start)
		wasActivated := <-activated
		waitForRuntimeCancellation(t, entry)
		if wasActivated && entry.state.Load() != natConn {
			t.Fatal("activation race lost the NAT socket state")
		}
		_ = natConn.Close()
		stop()
	}
}

func newRuntimeTestUDPConn() *net.UDPConn {
	// The state machine only requires pointer identity. A zero-value UDPConn lets
	// this race test run in restricted CI sandboxes without opening a socket.
	return new(net.UDPConn)
}

func waitForRuntimeCancellation(t *testing.T, entry *session) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !entry.runtimeCanceled.Load() {
		if time.Now().After(deadline) {
			t.Fatal("runtime cancellation callback did not run")
		}
		time.Sleep(time.Millisecond)
	}
}
