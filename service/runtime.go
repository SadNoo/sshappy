package service

import (
	"context"
	"errors"
	"net/netip"
	"strings"
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

// RuntimeTargetResolver is an optional extension for deployments that must
// validate the exact IP selected for a domain target. The relay uses the
// returned address for the outbound dial, so an implementation should return a
// literal IP address after successful resolution. Returning accepted=false
// rejects the request by policy; returning an error rejects it as a resolution
// failure.
type RuntimeTargetResolver interface {
	ResolveAndAcceptTarget(ctx context.Context, network, username string, source netip.AddrPort, target conn.Addr) (resolved conn.Addr, accepted bool, err error)
}

const runtimeTargetCacheMaxEntries = 64

var errRuntimeTargetCacheFull = errors.New("UDP session resolved-target cache is full")

// runtimeTargetCache pins the first resolved IP for each domain used by a
// UDP session. Caching avoids a DNS lookup per packet and makes the policy
// decision and actual destination stable for the lifetime of the session. The
// hard entry limit prevents an authenticated client from growing memory or
// issuing unbounded unique-domain resolutions through one session.
type runtimeTargetCache struct {
	entries map[string]netip.Addr
}

func (c *runtimeTargetCache) resolveAndAccept(ctx context.Context, observer RuntimeObserver, network, username string, source netip.AddrPort, target conn.Addr) (conn.Addr, bool, error) {
	if _, ok := observer.(RuntimeTargetResolver); !ok || !target.IsDomain() {
		return resolveRuntimeTarget(ctx, observer, network, username, source, target)
	}

	domain := target.Domain()
	if resolvedIP, ok := c.entries[domain]; ok {
		// Recheck the cached literal IP against the latest policy without doing
		// another DNS lookup.
		resolved := conn.AddrFromIPAndPort(resolvedIP, target.Port())
		return resolveRuntimeTarget(ctx, observer, network, username, source, resolved)
	}
	if len(c.entries) >= runtimeTargetCacheMaxEntries {
		return conn.Addr{}, false, errRuntimeTargetCacheFull
	}
	resolved, accepted, err := resolveRuntimeTarget(ctx, observer, network, username, source, target)
	if err != nil || !accepted {
		return resolved, accepted, err
	}
	if !resolved.IsIP() {
		return conn.Addr{}, false, errors.New("runtime target resolver returned a non-IP address")
	}
	if c.entries == nil {
		c.entries = make(map[string]netip.Addr)
	}
	c.entries[strings.Clone(domain)] = resolved.IP()
	return resolved, true, nil
}

// RuntimeSessionController is an optional extension for deployments that must
// terminate existing sessions when authorization changes. Implementations must
// make policy publication and registration atomic with respect to each other.
// The returned end function unregisters the session and must be safe to call
// exactly once via defer. A nil end function is reserved for observers that do
// not implement this extension.
type RuntimeSessionController interface {
	BeginSession(parent context.Context, network, username string, source netip.AddrPort, target conn.Addr) (sessionCtx context.Context, end func(), accepted bool)
}

// RuntimeTrafficDirection identifies the payload direction at the server.
type RuntimeTrafficDirection uint8

const (
	RuntimeTrafficUplink RuntimeTrafficDirection = iota
	RuntimeTrafficDownlink
)

// RuntimeTrafficLimiter is an optional extension for deployments that apply
// live per-node or per-user bandwidth limits. Implementations should return
// promptly when ctx is canceled.
type RuntimeTrafficLimiter interface {
	WaitTraffic(ctx context.Context, network, username string, direction RuntimeTrafficDirection, bytes int) error
}

func resolveRuntimeTarget(ctx context.Context, observer RuntimeObserver, network, username string, source netip.AddrPort, target conn.Addr) (conn.Addr, bool, error) {
	resolver, ok := observer.(RuntimeTargetResolver)
	if !ok {
		return target, true, nil
	}
	return resolver.ResolveAndAcceptTarget(ctx, network, username, source, target)
}

func beginRuntimeSession(parent context.Context, observer RuntimeObserver, network, username string, source netip.AddrPort, target conn.Addr) (context.Context, func(), bool) {
	controller, ok := observer.(RuntimeSessionController)
	if !ok {
		return parent, nil, true
	}
	return controller.BeginSession(parent, network, username, source, target)
}

func waitRuntimeTraffic(ctx context.Context, observer RuntimeObserver, network, username string, direction RuntimeTrafficDirection, bytes int) error {
	if observer == nil || bytes <= 0 {
		return nil
	}
	limiter, ok := observer.(RuntimeTrafficLimiter)
	if !ok {
		return nil
	}
	return limiter.WaitTraffic(ctx, network, username, direction, bytes)
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
