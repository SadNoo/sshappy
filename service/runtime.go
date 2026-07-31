package service

import (
	"context"
	"net/netip"
	"sync"

	"github.com/database64128/shadowsocks-go/api/ssm"
	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/stats"
)

// serviceLifecycle owns the context used by one running service instance.
// Stop paths cancel it before waiting for service goroutines, so work blocked
// in routing, name resolution, or dialing can return promptly.
type serviceLifecycle struct {
	mu     sync.Mutex
	cancel context.CancelFunc
}

func (l *serviceLifecycle) start(parent context.Context) context.Context {
	ctx, cancel := context.WithCancel(parent)

	l.mu.Lock()
	previousCancel := l.cancel
	l.cancel = cancel
	l.mu.Unlock()

	if previousCancel != nil {
		previousCancel()
	}
	return ctx
}

func (l *serviceLifecycle) stop() {
	l.mu.Lock()
	cancel := l.cancel
	l.cancel = nil
	l.mu.Unlock()

	if cancel != nil {
		cancel()
	}
}

// RuntimeObserver applies deployment-specific policy after authentication.
// Returning false rejects the packet or connection before routing.
type RuntimeObserver interface {
	Accept(network, username string, source netip.AddrPort, target conn.Addr) bool
	Observe(network, username string, source netip.AddrPort)
}

// SetRuntimeHooks injects deployment-specific statistics and policy hooks.
func (sc *ServerConfig) SetRuntimeHooks(collector stats.Collector, observer RuntimeObserver) {
	sc.runtimeCollector = collector
	sc.runtimeObserver = observer
}

// RuntimeServer returns the live credential manager and statistics collector.
func (m *Manager) RuntimeServer(name string) (ssm.Server, bool) {
	server, ok := m.serverByName[name]
	return server, ok
}
