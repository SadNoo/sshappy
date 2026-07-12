package service

import "testing"

func TestUDPSessionLimits(t *testing.T) {
	relay := &UDPSessionRelay{
		table:          make(map[uint64]*session),
		sessionsByUser: make(map[string]int),
	}
	listener := &udpRelayServerConn{
		maxSessions:        3,
		maxSessionsPerUser: 2,
	}

	if !relay.reserveSession("7", listener) {
		t.Fatal("first user session was rejected")
	}
	relay.table[1] = &session{username: "7"}
	if !relay.reserveSession("7", listener) {
		t.Fatal("second user session was rejected")
	}
	relay.table[2] = &session{username: "7"}
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
	relay.table[3] = &session{username: "8"}
	if relay.reserveSession("9", listener) {
		t.Fatal("global session limit was not enforced")
	}
	if relay.dropSessionLimit.Load() != 1 {
		t.Fatalf("dropSessionLimit = %d", relay.dropSessionLimit.Load())
	}

	delete(relay.table, 1)
	relay.releaseSession("7")
	if !relay.reserveSession("7", listener) {
		t.Fatal("released per-user capacity was not reusable")
	}
}

func TestUDPSessionLimitsDisabled(t *testing.T) {
	relay := &UDPSessionRelay{
		table:          make(map[uint64]*session),
		sessionsByUser: make(map[string]int),
	}
	listener := &udpRelayServerConn{}

	for i := 0; i < 4096; i++ {
		if !relay.reserveSession("7", listener) {
			t.Fatalf("unlimited listener rejected session %d", i)
		}
		relay.table[uint64(i)] = &session{username: "7"}
	}
}
