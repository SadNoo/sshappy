package service

import (
	"context"
	"net"
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

// SessionIdentity is the immutable billing and authorization identity captured
// immediately after a client authenticates. Deployments that rotate credentials
// or policies must never derive this tuple again from mutable runtime state.
type SessionIdentity struct {
	UserID            string
	CredentialVersion int64
	PolicyVersion     int64
}

// RuntimeTrafficDirection identifies which side of a runtime session consumed
// traffic quota.
type RuntimeTrafficDirection uint8

const (
	RuntimeTrafficUplink RuntimeTrafficDirection = iota + 1
	RuntimeTrafficDownlink
)

// RuntimeTrafficReservation temporarily removes bytes from a session's shared
// quota before a network write. Commit records the confirmed prefix and refunds
// the rest. Refund releases the full reservation after a rejected or failed
// write. Implementations must make both operations idempotent.
type RuntimeTrafficReservation interface {
	Bytes() uint64
	Commit(confirmedBytes uint64)
	Refund()
}

// RuntimeSession is an optional authenticated-session contract used by the
// Flysky control plane. The service package deliberately treats it as opaque so
// ordinary panel and standalone deployments continue to use RuntimeObserver and
// stats.Collector unchanged.
type RuntimeSession interface {
	Identity() SessionIdentity
	Context() context.Context
	Active() bool
	Observe(source netip.AddrPort)
	ReserveTraffic(direction RuntimeTrafficDirection, packets, bytes uint64) RuntimeTrafficReservation
	Close()
}

// RuntimeSessionFactory captures a stable runtime session after protocol
// authentication. Returning false rejects the connection or packet.
type RuntimeSessionFactory interface {
	OpenRuntimeSession(network, username string, source netip.AddrPort, target conn.Addr) (RuntimeSession, bool)
}

func runtimeSessionFactory(observer RuntimeObserver) RuntimeSessionFactory {
	factory, _ := observer.(RuntimeSessionFactory)
	return factory
}

func reserveFullRuntimeTraffic(
	session RuntimeSession,
	direction RuntimeTrafficDirection,
	packets, bytes uint64,
) (RuntimeTrafficReservation, bool) {
	if session == nil || bytes == 0 {
		return nil, true
	}
	reservation := session.ReserveTraffic(direction, packets, bytes)
	if reservation == nil {
		return nil, false
	}
	if reservation.Bytes() != bytes {
		reservation.Refund()
		return nil, false
	}
	return reservation, true
}

// settleRuntimeTrafficBatchResult applies one sendmmsg result to a batch. The
// confirmed prefix is committed; when the syscall reported an error, the first
// failed entry is refunded and skipped so a later attempt can continue with the
// untouched suffix. Callers retain deferred Refund guards for every entry.
func settleRuntimeTrafficBatchResult(
	reservations []RuntimeTrafficReservation,
	payloadBytes []uint64,
	confirmed int,
	skipFailed bool,
) (sentPackets int, sentBytes uint64, advance int) {
	confirmed = min(confirmed, len(reservations), len(payloadBytes))
	for index := range confirmed {
		if reservation := reservations[index]; reservation != nil {
			reservation.Commit(payloadBytes[index])
		}
		sentBytes += payloadBytes[index]
	}
	advance = confirmed
	if skipFailed && confirmed < len(reservations) {
		if reservation := reservations[confirmed]; reservation != nil {
			reservation.Refund()
		}
		advance++
	}
	return confirmed, sentBytes, advance
}

func closeConnectionsOnRuntimeEnd(session RuntimeSession, connections ...net.Conn) func() bool {
	if session == nil {
		return func() bool { return true }
	}
	return context.AfterFunc(session.Context(), func() {
		for _, connection := range connections {
			if connection == nil {
				continue
			}
			_ = connection.SetDeadline(conn.ALongTimeAgo)
			_ = connection.Close()
		}
	})
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
