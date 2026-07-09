package service

import (
	"net/netip"

	"github.com/database64128/shadowsocks-go/api/ssm"
	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/stats"
)

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
