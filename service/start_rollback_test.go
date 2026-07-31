package service

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/stats"
	"go.uber.org/zap"
)

const lifecycleTestTimeout = time.Second

func TestTCPRelayRollbackCancelsHandlersBeforeWaiting(t *testing.T) {
	relay := &TCPRelay{connections: make(map[net.Conn]struct{})}
	runCtx := relay.lifecycle.start(context.Background())
	relay.handlerWg.Go(func() {
		<-runCtx.Done()
	})

	done := make(chan error, 1)
	go func() {
		done <- relay.rollbackStart()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(lifecycleTestTimeout):
		t.Fatal("rollback waited for a handler without cancelling its context")
	}
}

func TestUDPRelayStopCancelsSessionsBeforeWaiting(t *testing.T) {
	relay := &UDPSessionRelay{
		logger:             zap.NewNop(),
		table:              make(map[udpSessionKey]*session),
		sessionsByListener: make(map[*net.UDPConn]int),
		sessionsByUser:     make(map[udpSessionUserKey]int),
	}
	runCtx := relay.lifecycle.start(context.Background())
	relay.wg.Go(func() {
		<-runCtx.Done()
	})

	done := make(chan error, 1)
	go func() {
		done <- relay.Stop()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(lifecycleTestTimeout):
		t.Fatal("Stop waited for a session without cancelling its context")
	}
}

func TestUDPNATRelayStopCancelsSessionsBeforeWaiting(t *testing.T) {
	relay := &UDPNATRelay{
		logger: zap.NewNop(),
		table:  make(map[udpNATKey]*natEntry),
	}
	runCtx := relay.lifecycle.start(context.Background())
	relay.wg.Go(func() {
		<-runCtx.Done()
	})

	done := make(chan error, 1)
	go func() {
		done <- relay.Stop()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(lifecycleTestTimeout):
		t.Fatal("Stop waited for a NAT session without cancelling its context")
	}
}

func TestTCPRelayStartRollsBackEarlierListener(t *testing.T) {
	blocker, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()

	listenConfig := conn.NewListenConfigCache().Get(conn.ListenerSocketOptions{})
	relay := NewTCPRelay(0, "test", []tcpRelayListener{
		{
			listenConfig:   listenConfig,
			handshakeSlots: make(chan struct{}, 1),
			network:        "tcp4",
			address:        "127.0.0.1:0",
		},
		{
			listenConfig:   listenConfig,
			handshakeSlots: make(chan struct{}, 1),
			network:        "tcp4",
			address:        blocker.Addr().String(),
		},
	}, nil, stats.NoopCollector{}, nil, nil, zap.NewNop())

	if err := relay.Start(context.Background()); err == nil {
		t.Fatal("Start succeeded despite occupied second address")
	}
	first := relay.listeners[0].listener
	if first == nil {
		t.Fatal("first listener was never opened")
	}
	if err := first.Close(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("first listener remained open after rollback: Close error = %v", err)
	}
}

func TestUDPRelayStartRollsBackEarlierListener(t *testing.T) {
	blocker, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()

	listenConfig := conn.NewListenConfigCache().Get(conn.ListenerSocketOptions{})
	relay := NewUDPSessionRelay("test", 0, 1500, 0, 1500, 1500, []udpRelayServerConn{
		{
			listenConfig: listenConfig,
			network:      "udp4",
			address:      "127.0.0.1:0",
			batchMode:    "no",
		},
		{
			listenConfig: listenConfig,
			network:      "udp4",
			address:      blocker.LocalAddr().String(),
			batchMode:    "no",
		},
	}, nil, stats.NoopCollector{}, nil, nil, zap.NewNop())

	if err := relay.Start(context.Background()); err == nil {
		t.Fatal("Start succeeded despite occupied second address")
	}
	first := relay.listeners[0].serverConn
	if first == nil {
		t.Fatal("first UDP listener was never opened")
	}
	if err := first.Close(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("first UDP listener remained open after rollback: Close error = %v", err)
	}
}
