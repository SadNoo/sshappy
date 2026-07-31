package service

import (
	"net"
	"net/netip"
	"testing"
)

func TestUDPSessionLimits(t *testing.T) {
	relay := &UDPSessionRelay{
		table:              make(map[udpSessionKey]*session),
		sessionsByListener: make(map[*net.UDPConn]int),
		sessionsByUser:     make(map[udpSessionUserKey]int),
	}
	serverConn := &net.UDPConn{}
	listener := &udpRelayServerConn{
		serverConn:         serverConn,
		maxSessions:        3,
		maxSessionsPerUser: 2,
	}

	if !relay.reserveSession("7", listener) {
		t.Fatal("first user session was rejected")
	}
	relay.table[udpSessionKey{serverConn: serverConn, clientSessionID: 1}] = &session{serverConn: serverConn, username: "7"}
	if !relay.reserveSession("7", listener) {
		t.Fatal("second user session was rejected")
	}
	relay.table[udpSessionKey{serverConn: serverConn, clientSessionID: 2}] = &session{serverConn: serverConn, username: "7"}
	if relay.reserveSession("7", listener) {
		t.Fatal("per-user session limit was not enforced")
	}
	if relay.dropUserSessionLimit.Load() != 1 {
		t.Fatalf("dropUserSessionLimit = %d", relay.dropUserSessionLimit.Load())
	}
	if relay.lastLimitedUser != "7" {
		t.Fatalf("lastLimitedUser = %q", relay.lastLimitedUser)
	}

	if !relay.reserveSession("8", listener) {
		t.Fatal("session for another user was rejected")
	}
	relay.table[udpSessionKey{serverConn: serverConn, clientSessionID: 3}] = &session{serverConn: serverConn, username: "8"}
	if relay.reserveSession("9", listener) {
		t.Fatal("global session limit was not enforced")
	}
	if relay.dropSessionLimit.Load() != 1 {
		t.Fatalf("dropSessionLimit = %d", relay.dropSessionLimit.Load())
	}

	delete(relay.table, udpSessionKey{serverConn: serverConn, clientSessionID: 1})
	relay.releaseSession(serverConn, "7")
	if !relay.reserveSession("7", listener) {
		t.Fatal("released per-user capacity was not reusable")
	}
}

func TestUDPSessionLimitsDisabled(t *testing.T) {
	relay := &UDPSessionRelay{
		table:              make(map[udpSessionKey]*session),
		sessionsByListener: make(map[*net.UDPConn]int),
		sessionsByUser:     make(map[udpSessionUserKey]int),
	}
	serverConn := &net.UDPConn{}
	listener := &udpRelayServerConn{serverConn: serverConn}

	for i := 0; i < 4096; i++ {
		if !relay.reserveSession("7", listener) {
			t.Fatalf("unlimited listener rejected session %d", i)
		}
		relay.table[udpSessionKey{serverConn: serverConn, clientSessionID: uint64(i)}] = &session{serverConn: serverConn, username: "7"}
	}
}

func TestUDPSessionLimitsAreScopedToListener(t *testing.T) {
	relay := &UDPSessionRelay{
		table:              make(map[udpSessionKey]*session),
		sessionsByListener: make(map[*net.UDPConn]int),
		sessionsByUser:     make(map[udpSessionUserKey]int),
	}
	firstConn := &net.UDPConn{}
	secondConn := &net.UDPConn{}
	first := &udpRelayServerConn{serverConn: firstConn, maxSessions: 2, maxSessionsPerUser: 1}
	second := &udpRelayServerConn{serverConn: secondConn, maxSessions: 2, maxSessionsPerUser: 1}

	if !relay.reserveSession("alice", first) {
		t.Fatal("first listener rejected alice's first session")
	}
	if !relay.reserveSession("alice", second) {
		t.Fatal("second listener inherited alice's limit from first listener")
	}
	if relay.reserveSession("alice", first) {
		t.Fatal("first listener did not enforce its per-user limit")
	}
	if !relay.reserveSession("bob", first) {
		t.Fatal("first listener rejected a session within its total limit")
	}
	if relay.reserveSession("charlie", first) {
		t.Fatal("first listener did not enforce its total limit")
	}
	if !relay.reserveSession("bob", second) {
		t.Fatal("second listener inherited the first listener's total limit")
	}

	relay.releaseSession(firstConn, "alice")
	if !relay.reserveSession("alice", first) {
		t.Fatal("released capacity was not returned to the correct listener")
	}
}

func TestUDPSessionKeyIncludesListener(t *testing.T) {
	first := &net.UDPConn{}
	second := &net.UDPConn{}
	firstKey := udpSessionKey{serverConn: first, clientSessionID: 42}
	secondKey := udpSessionKey{serverConn: second, clientSessionID: 42}
	if firstKey == secondKey {
		t.Fatal("equal client session IDs on different listeners share a key")
	}
}

func TestUDPNATKeyIncludesListener(t *testing.T) {
	first := &net.UDPConn{}
	second := &net.UDPConn{}
	client := netip.MustParseAddrPort("192.0.2.1:1234")
	firstKey := udpNATKey{serverConn: first, clientAddrPort: client}
	secondKey := udpNATKey{serverConn: second, clientAddrPort: client}
	if firstKey == secondKey {
		t.Fatal("equal client addresses on different listeners share a NAT key")
	}
}
