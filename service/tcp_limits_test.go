package service

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestTCPPerUserConnectionLimit(t *testing.T) {
	relay := &TCPRelay{connectionsByUser: make(map[string]int)}

	if !relay.reserveUserConnection("7", 2) || !relay.reserveUserConnection("7", 2) {
		t.Fatal("connections below the per-user limit were rejected")
	}
	if relay.reserveUserConnection("7", 2) {
		t.Fatal("connection above the per-user limit was accepted")
	}
	if !relay.reserveUserConnection("8", 2) {
		t.Fatal("another user was affected by the first user's limit")
	}
	if relay.rejectedUserLimit.Load() != 1 || relay.lastLimitedUser != "7" {
		t.Fatalf("unexpected rejection state: rejected=%d user=%q", relay.rejectedUserLimit.Load(), relay.lastLimitedUser)
	}

	relay.releaseUserConnection("7")
	if !relay.reserveUserConnection("7", 2) {
		t.Fatal("released connection capacity was not reusable")
	}
	if relay.peakUserConnections.Load() != 3 {
		t.Fatalf("peakUserConnections = %d, want 3", relay.peakUserConnections.Load())
	}
}

func TestTCPPerUserConnectionLimitDisabled(t *testing.T) {
	relay := &TCPRelay{connectionsByUser: make(map[string]int)}
	for i := 0; i < 1000; i++ {
		if !relay.reserveUserConnection("7", 0) {
			t.Fatalf("unlimited connection %d was rejected", i)
		}
	}
}

func TestTCPPerUserConnectionLimitConcurrent(t *testing.T) {
	const limit = 80
	const attempts = 200
	relay := &TCPRelay{connectionsByUser: make(map[string]int)}
	start := make(chan struct{})
	release := make(chan struct{})
	var accepted atomic.Int64
	var attempted sync.WaitGroup
	var finished sync.WaitGroup
	attempted.Add(attempts)
	finished.Add(attempts)

	for range attempts {
		go func() {
			defer finished.Done()
			<-start
			ok := relay.reserveUserConnection("7", limit)
			if ok {
				accepted.Add(1)
			}
			attempted.Done()
			if ok {
				<-release
				relay.releaseUserConnection("7")
			}
		}()
	}

	close(start)
	attempted.Wait()
	if got := accepted.Load(); got != limit {
		t.Fatalf("accepted = %d, want %d", got, limit)
	}
	if got := relay.rejectedUserLimit.Load(); got != attempts-limit {
		t.Fatalf("rejected = %d, want %d", got, attempts-limit)
	}
	close(release)
	finished.Wait()
	if relay.activeUserConnections.Load() != 0 || len(relay.connectionsByUser) != 0 {
		t.Fatalf("connection state was not released: active=%d users=%v", relay.activeUserConnections.Load(), relay.connectionsByUser)
	}
}
