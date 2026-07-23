package flyskynode

import (
	"net/netip"
	"testing"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
)

func TestRuntimeUsesUUIDPoliciesAndFailsClosed(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	userID := "20000000-0000-4000-8000-000000000002"
	state := NewState()
	runtime := NewRuntime(state)
	runtime.now = func() time.Time { return now }
	runtime.ReplaceUsers(now.Add(time.Hour), []User{{
		ID: userID, CredentialVersion: 3, ValidUntil: now.Add(30 * time.Minute), QuotaRemainingBytes: 1024,
	}})
	source := netip.MustParseAddrPort("192.0.2.10:12345")
	if !runtime.Accept("tcp", userID, source, conn.Addr{}) {
		t.Fatal("active UUID user was rejected")
	}
	if runtime.Accept("tcp", "30000000-0000-4000-8000-000000000003", source, conn.Addr{}) {
		t.Fatal("unknown UUID user was accepted")
	}
	runtime.Observe("tcp", userID, source)
	runtime.CollectTCPSession(userID, 80, 100)
	deltas := state.SnapshotTraffic()
	if len(deltas) != 1 || deltas[0].UserID != userID || deltas[0].CredentialVersion != 3 ||
		deltas[0].UploadBytes != 100 || deltas[0].DownloadBytes != 80 {
		t.Fatalf("traffic = %+v", deltas)
	}
	if online := state.OnlineUserCount(time.Minute); online != 1 {
		t.Fatalf("online users = %d", online)
	}

	now = now.Add(31 * time.Minute)
	if runtime.Accept("tcp", userID, source, conn.Addr{}) {
		t.Fatal("expired user was accepted")
	}
	now = now.Add(30 * time.Minute)
	if runtime.Accept("tcp", userID, source, conn.Addr{}) {
		t.Fatal("expired snapshot was accepted")
	}
}

func TestRuntimeRejectsZeroQuota(t *testing.T) {
	t.Parallel()

	now := time.Now()
	runtime := NewRuntime(NewState())
	runtime.now = func() time.Time { return now }
	runtime.ReplaceUsers(now.Add(time.Hour), []User{{
		ID: "20000000-0000-4000-8000-000000000002", CredentialVersion: 1,
		ValidUntil: now.Add(time.Hour), QuotaRemainingBytes: 0,
	}})
	if runtime.Accept("udp", "20000000-0000-4000-8000-000000000002", netip.AddrPort{}, conn.Addr{}) {
		t.Fatal("zero-quota user was accepted")
	}
}

func TestRuntimeAcceptsUnlimitedUser(t *testing.T) {
	t.Parallel()

	now := time.Now()
	const userID = "20000000-0000-4000-8000-000000000002"
	runtime := NewRuntime(NewState())
	runtime.now = func() time.Time { return now }
	runtime.ReplaceUsers(now.Add(time.Hour), []User{{
		ID: userID, CredentialVersion: 1, ValidUntil: now.Add(time.Hour), Unlimited: true,
	}})
	if !runtime.Accept("udp", userID, netip.AddrPort{}, conn.Addr{}) {
		t.Fatal("unlimited user was rejected")
	}
}

func TestAliveSummaryCountsUniqueIPsWithoutExportingAddresses(t *testing.T) {
	t.Parallel()
	state := NewState()
	state.AddAliveIP("10000000-0000-4000-8000-000000000001", "192.0.2.1")
	state.AddAliveIP("10000000-0000-4000-8000-000000000001", "192.0.2.2")
	state.AddAliveIP("20000000-0000-4000-8000-000000000002", "192.0.2.1")
	onlineIPs, activeUsers := state.AliveSummary(time.Minute, time.Now())
	if onlineIPs != 2 || activeUsers != 2 {
		t.Fatalf("online IPs=%d active users=%d", onlineIPs, activeUsers)
	}
	onlineIPs, activeUsers = state.AliveSummary(time.Minute, time.Now().Add(2*time.Minute))
	if onlineIPs != 0 || activeUsers != 0 {
		t.Fatalf("expired online IPs=%d active users=%d", onlineIPs, activeUsers)
	}
}
