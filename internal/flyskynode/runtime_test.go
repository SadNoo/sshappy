package flyskynode

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/service"
)

func TestRuntimeUsesUUIDPoliciesAndFailsClosed(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	userID := "20000000-0000-4000-8000-000000000002"
	state := NewState()
	runtime := NewRuntime(state)
	runtime.now = func() time.Time { return now }
	user := User{
		ID: userID, CredentialVersion: 3, ValidUntil: now.Add(30 * time.Minute), QuotaRemainingBytes: 1024,
		PolicyVersion: 1,
	}
	runtime.ReplaceUsers(now.Add(time.Hour), []User{user})
	label := credentialLabel(user)
	source := netip.MustParseAddrPort("192.0.2.10:12345")
	if !runtime.Accept("tcp", label, source, conn.Addr{}) {
		t.Fatal("active UUID user was rejected")
	}
	if runtime.Accept("tcp", "30000000-0000-4000-8000-000000000003", source, conn.Addr{}) {
		t.Fatal("unknown UUID user was accepted")
	}
	runtime.Observe("tcp", label, source)
	runtime.CollectTCPSession(label, 80, 100)
	deltas := state.SnapshotTraffic()
	if len(deltas) != 1 || deltas[0].UserID != userID || deltas[0].CredentialVersion != 3 ||
		deltas[0].UploadBytes != 100 || deltas[0].DownloadBytes != 80 {
		t.Fatalf("traffic = %+v", deltas)
	}
	if online := state.OnlineUserCount(time.Minute); online != 1 {
		t.Fatalf("online users = %d", online)
	}

	now = now.Add(31 * time.Minute)
	if runtime.Accept("tcp", label, source, conn.Addr{}) {
		t.Fatal("expired user was accepted")
	}
	now = now.Add(30 * time.Minute)
	if runtime.Accept("tcp", label, source, conn.Addr{}) {
		t.Fatal("expired snapshot was accepted")
	}
}

func TestRuntimeRejectsZeroQuota(t *testing.T) {
	t.Parallel()

	now := time.Now()
	runtime := NewRuntime(NewState())
	runtime.now = func() time.Time { return now }
	user := User{
		ID: "20000000-0000-4000-8000-000000000002", CredentialVersion: 1,
		ValidUntil: now.Add(time.Hour), QuotaRemainingBytes: 0, PolicyVersion: 1,
	}
	runtime.ReplaceUsers(now.Add(time.Hour), []User{user})
	if runtime.Accept("udp", credentialLabel(user), netip.AddrPort{}, conn.Addr{}) {
		t.Fatal("zero-quota user was accepted")
	}
}

func TestRuntimeRejectsNegativeQuota(t *testing.T) {
	t.Parallel()

	now := time.Now()
	runtime := NewRuntime(NewState())
	runtime.now = func() time.Time { return now }
	user := User{
		ID: "20000000-0000-4000-8000-000000000002", CredentialVersion: 1,
		ValidUntil: now.Add(time.Hour), QuotaRemainingBytes: -1, PolicyVersion: 1,
	}
	runtime.ReplaceUsers(now.Add(time.Hour), []User{user})
	if runtime.Accept("tcp", credentialLabel(user), netip.AddrPort{}, conn.Addr{}) {
		t.Fatal("negative quota wrapped to a positive allowance")
	}
}

func TestRuntimeAcceptsUnlimitedUser(t *testing.T) {
	t.Parallel()

	now := time.Now()
	const userID = "20000000-0000-4000-8000-000000000002"
	runtime := NewRuntime(NewState())
	runtime.now = func() time.Time { return now }
	user := User{
		ID: userID, CredentialVersion: 1, ValidUntil: now.Add(time.Hour), Unlimited: true,
		PolicyVersion: 1,
	}
	runtime.ReplaceUsers(now.Add(time.Hour), []User{user})
	if !runtime.Accept("udp", credentialLabel(user), netip.AddrPort{}, conn.Addr{}) {
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

func TestStateKeepsCredentialVersionsSeparate(t *testing.T) {
	t.Parallel()
	const userID = "20000000-0000-4000-8000-000000000002"
	state := NewState()
	state.AddTraffic(userID, 1, 10, 20)
	state.AddTraffic(userID, 2, 30, 40)
	deltas := state.SnapshotTraffic()
	if len(deltas) != 2 || deltas[0].CredentialVersion != 1 || deltas[1].CredentialVersion != 2 {
		t.Fatalf("credential-scoped traffic = %+v", deltas)
	}
}

func TestRuntimeSessionFreezesIdentityAndAttributesTailTraffic(t *testing.T) {
	t.Parallel()
	now := time.Now()
	const userID = "20000000-0000-4000-8000-000000000002"
	state := NewState()
	runtime := NewRuntime(state)
	oldUser := User{
		ID: userID, CredentialVersion: 3, PolicyVersion: 7,
		ValidUntil: now.Add(time.Hour), QuotaRemainingBytes: 100,
	}
	runtime.ReplaceUsers(now.Add(time.Hour), []User{oldUser})
	session := openRuntimeSessionForTest(t, runtime, oldUser)
	reservation := session.ReserveTraffic(service.RuntimeTrafficUplink, 0, 25)
	if reservation == nil || reservation.Bytes() != 25 {
		t.Fatalf("tail reservation = %#v", reservation)
	}

	newUser := oldUser
	newUser.CredentialVersion = 4
	newUser.PolicyVersion = 8
	runtime.ReplaceUsers(now.Add(time.Hour), []User{newUser})
	select {
	case <-session.Context().Done():
	default:
		t.Fatal("old tuple session remained active after credential/policy change")
	}
	reservation.Commit(25)
	session.Close()

	deltas := state.SnapshotTraffic()
	if len(deltas) != 1 || deltas[0].CredentialVersion != 3 || deltas[0].UploadBytes != 25 {
		t.Fatalf("tail traffic identity = %+v", deltas)
	}
	newSession := openRuntimeSessionForTest(t, runtime, newUser)
	newSession.Close()
}

func TestRuntimeQuotaReservationsNeverConfirmBeyondRemaining(t *testing.T) {
	t.Parallel()
	now := time.Now()
	user := User{
		ID: "20000000-0000-4000-8000-000000000002", CredentialVersion: 1, PolicyVersion: 1,
		ValidUntil: now.Add(time.Hour), QuotaRemainingBytes: 1000,
	}
	state := NewState()
	runtime := NewRuntime(state)
	runtime.ReplaceUsers(now.Add(time.Hour), []User{user})
	session := openRuntimeSessionForTest(t, runtime, user)
	defer session.Close()

	var wg sync.WaitGroup
	for range 128 {
		wg.Go(func() {
			reservation := session.ReserveTraffic(service.RuntimeTrafficUplink, 0, 17)
			if reservation != nil {
				reservation.Commit(reservation.Bytes())
			}
		})
	}
	wg.Wait()
	deltas := state.SnapshotTraffic()
	var confirmed int64
	for _, delta := range deltas {
		confirmed += delta.UploadBytes + delta.DownloadBytes
	}
	if confirmed != 1000 {
		t.Fatalf("confirmed bytes = %d, want exact quota 1000", confirmed)
	}
	if reservation := session.ReserveTraffic(service.RuntimeTrafficDownlink, 0, 1); reservation != nil {
		t.Fatal("exhausted quota accepted another reservation")
	}
}

func TestRuntimeQuotaReductionBoundsTailToExistingReservation(t *testing.T) {
	t.Parallel()
	now := time.Now()
	user := User{
		ID: "20000000-0000-4000-8000-000000000002", CredentialVersion: 1, PolicyVersion: 1,
		ValidUntil: now.Add(time.Hour), QuotaRemainingBytes: 100,
	}
	state := NewState()
	runtime := NewRuntime(state)
	runtime.ReplaceUsers(now.Add(time.Hour), []User{user})
	session := openRuntimeSessionForTest(t, runtime, user)
	reservation := session.ReserveTraffic(service.RuntimeTrafficUplink, 0, 80)
	if reservation == nil || reservation.Bytes() != 80 {
		t.Fatalf("in-flight reservation = %#v", reservation)
	}

	// A lower authoritative remaining value cannot revoke bytes already handed
	// to an in-flight write. It does stop the session and prevents every new
	// reservation, bounding any post-update tail to the 80 bytes already held.
	user.QuotaRemainingBytes = 10
	runtime.ReplaceUsers(now.Add(time.Hour), []User{user})
	select {
	case <-session.Context().Done():
		t.Fatal("quota reduction killed a session while its only bytes were still in flight")
	default:
	}
	if next := session.ReserveTraffic(service.RuntimeTrafficDownlink, 0, 1); next != nil {
		t.Fatal("quota reduction allowed a new reservation")
	}
	reservation.Commit(80)
	select {
	case <-session.Context().Done():
	default:
		t.Fatal("confirmed exhaustion did not invalidate the live session")
	}
	session.Close()
	deltas := state.SnapshotTraffic()
	if len(deltas) != 1 || deltas[0].UploadBytes != 80 {
		t.Fatalf("bounded in-flight tail = %+v, want 80 bytes", deltas)
	}
}

func TestRuntimeQuotaReductionRefundRestoresOnlyNewCeiling(t *testing.T) {
	t.Parallel()
	now := time.Now()
	user := User{
		ID: "20000000-0000-4000-8000-000000000002", CredentialVersion: 1, PolicyVersion: 1,
		ValidUntil: now.Add(time.Hour), QuotaRemainingBytes: 100,
	}
	runtime := NewRuntime(NewState())
	runtime.ReplaceUsers(now.Add(time.Hour), []User{user})
	session := openRuntimeSessionForTest(t, runtime, user)
	inFlight := session.ReserveTraffic(service.RuntimeTrafficUplink, 0, 80)
	user.QuotaRemainingBytes = 10
	runtime.ReplaceUsers(now.Add(time.Hour), []User{user})
	inFlight.Refund()
	restored := session.ReserveTraffic(service.RuntimeTrafficDownlink, 0, 100)
	if restored == nil || restored.Bytes() != 10 {
		t.Fatalf("refunded allowance = %#v, want reduced ceiling 10", restored)
	}
	restored.Refund()
	session.Close()
}

func TestRuntimeZeroQuotaAndTupleChangeInvalidateAllSessions(t *testing.T) {
	t.Parallel()
	now := time.Now()
	user := User{
		ID: "20000000-0000-4000-8000-000000000002", CredentialVersion: 1, PolicyVersion: 1,
		ValidUntil: now.Add(time.Hour), QuotaRemainingBytes: 100,
	}
	runtime := NewRuntime(NewState())
	runtime.ReplaceUsers(now.Add(time.Hour), []User{user})
	first := openRuntimeSessionForTest(t, runtime, user)
	second := openRuntimeSessionForTest(t, runtime, user)

	zero := user
	zero.QuotaRemainingBytes = 0
	runtime.ReplaceUsers(now.Add(time.Hour), []User{zero})
	for index, session := range []*runtimeSession{first, second} {
		select {
		case <-session.Context().Done():
		default:
			t.Fatalf("zero quota left session %d active", index)
		}
		session.Close()
	}
	if _, ok := runtime.OpenRuntimeSession("tcp", credentialLabel(zero), netip.AddrPort{}, conn.Addr{}); ok {
		t.Fatal("zero quota accepted a new session")
	}

	restored := user
	restored.PolicyVersion = 2
	runtime.ReplaceUsers(now.Add(time.Hour), []User{restored})
	oldTuple := openRuntimeSessionForTest(t, runtime, restored)
	rotated := restored
	rotated.CredentialVersion = 2
	rotated.PolicyVersion = 3
	runtime.ReplaceUsers(now.Add(time.Hour), []User{rotated})
	select {
	case <-oldTuple.Context().Done():
	default:
		t.Fatal("tuple change left the old session active")
	}
	oldTuple.Close()
	newTuple := openRuntimeSessionForTest(t, runtime, rotated)
	newTuple.Close()
}

func TestLimitedReservationSettlesAcrossUnlimitedPolicyTransition(t *testing.T) {
	t.Parallel()
	now := time.Now()
	user := User{
		ID: "20000000-0000-4000-8000-000000000002", CredentialVersion: 1, PolicyVersion: 1,
		ValidUntil: now.Add(time.Hour), QuotaRemainingBytes: 100,
	}
	runtime := NewRuntime(NewState())
	runtime.ReplaceUsers(now.Add(time.Hour), []User{user})
	session := openRuntimeSessionForTest(t, runtime, user)
	reservation := session.ReserveTraffic(service.RuntimeTrafficUplink, 0, 40)
	if reservation == nil {
		t.Fatal("limited reservation was rejected")
	}

	unlimited := user
	unlimited.Unlimited = true
	runtime.ReplaceUsers(now.Add(time.Hour), []User{unlimited})
	reservation.Commit(20)

	limitedAgain := user
	limitedAgain.QuotaRemainingBytes = 80
	runtime.ReplaceUsers(now.Add(time.Hour), []User{limitedAgain})
	ledger := runtime.ledgers[session.identity]
	ledger.mu.Lock()
	reserved, available := ledger.reserved, ledger.available
	ledger.mu.Unlock()
	if reserved != 0 || available != 80 {
		t.Fatalf("ledger after limited->unlimited->settle->limited = reserved %d available %d", reserved, available)
	}
	session.Close()
}

func TestStaleExhaustionCannotInvalidateRestoredUnlimitedSession(t *testing.T) {
	t.Parallel()
	now := time.Now()
	user := User{
		ID: "20000000-0000-4000-8000-000000000002", CredentialVersion: 1, PolicyVersion: 1,
		ValidUntil: now.Add(time.Hour), QuotaRemainingBytes: 1,
	}
	runtime := NewRuntime(NewState())
	runtime.ReplaceUsers(now.Add(time.Hour), []User{user})
	session := openRuntimeSessionForTest(t, runtime, user)
	ledger := runtime.ledgers[session.identity]
	reservation := session.ReserveTraffic(service.RuntimeTrafficUplink, 0, 1)
	if reservation == nil {
		t.Fatal("final-byte reservation was rejected")
	}
	reservation.Commit(1)

	// Model the old settle/invalidate window: after an exhaustion candidate was
	// observed, a newer policy can restore the same tuple as unlimited before
	// invalidation claims runtime.mu. The recheck must preserve the new session.
	unlimited := user
	unlimited.Unlimited = true
	runtime.ReplaceUsers(now.Add(time.Hour), []User{unlimited})
	restored := openRuntimeSessionForTest(t, runtime, unlimited)
	runtime.invalidateIdentityIfExhausted(restored.identity, ledger)
	if !restored.Active() {
		t.Fatal("stale exhaustion invalidated a restored unlimited session")
	}
	restored.Close()
	session.Close()
}

func TestRuntimePartialCommitAndRefundRestoreExactAllowance(t *testing.T) {
	t.Parallel()
	now := time.Now()
	user := User{
		ID: "20000000-0000-4000-8000-000000000002", CredentialVersion: 1, PolicyVersion: 1,
		ValidUntil: now.Add(time.Hour), QuotaRemainingBytes: 10,
	}
	runtime := NewRuntime(NewState())
	runtime.ReplaceUsers(now.Add(time.Hour), []User{user})
	session := openRuntimeSessionForTest(t, runtime, user)
	partial := session.ReserveTraffic(service.RuntimeTrafficUplink, 0, 5)
	partial.Commit(3)
	refunded := session.ReserveTraffic(service.RuntimeTrafficDownlink, 0, 4)
	refunded.Refund()
	remaining := session.ReserveTraffic(service.RuntimeTrafficUplink, 0, 100)
	if remaining == nil || remaining.Bytes() != 7 {
		t.Fatalf("remaining reservation = %#v, want exactly 7 bytes", remaining)
	}
	remaining.Refund()
	session.Close()
}

func TestStaleDeadlineCannotCancelRefreshedSession(t *testing.T) {
	t.Parallel()
	now := time.Now()
	user := User{
		ID: "20000000-0000-4000-8000-000000000002", CredentialVersion: 1, PolicyVersion: 1,
		ValidUntil: now.Add(time.Hour), Unlimited: true,
	}
	runtime := NewRuntime(NewState())
	runtime.ReplaceUsers(now.Add(time.Hour), []User{user})
	session := openRuntimeSessionForTest(t, runtime, user)
	session.timerMu.Lock()
	staleTimerID := session.timerID
	session.timerMu.Unlock()

	user.ValidUntil = now.Add(2 * time.Hour)
	runtime.ReplaceUsers(now.Add(2*time.Hour), []User{user})
	session.expireDeadline(staleTimerID)
	if !session.Active() {
		t.Fatal("stale timer canceled a refreshed session")
	}
	session.Close()
}

func TestCurrentDeadlineInvalidatesSession(t *testing.T) {
	t.Parallel()
	now := time.Now()
	user := User{
		ID: "20000000-0000-4000-8000-000000000002", CredentialVersion: 1, PolicyVersion: 1,
		ValidUntil: now.Add(time.Hour), Unlimited: true,
	}
	runtime := NewRuntime(NewState())
	runtime.ReplaceUsers(now.Add(time.Hour), []User{user})
	session := openRuntimeSessionForTest(t, runtime, user)
	session.timerMu.Lock()
	currentTimerID := session.timerID
	session.timerMu.Unlock()
	session.expireDeadline(currentTimerID)
	select {
	case <-session.Context().Done():
	default:
		t.Fatal("current deadline did not invalidate the session")
	}
	session.Close()
}

func TestRuntimeGarbageCollectsInactiveLedgersAfterReservationsSettle(t *testing.T) {
	t.Parallel()
	now := time.Now()
	user := User{
		ID: "20000000-0000-4000-8000-000000000002", CredentialVersion: 1, PolicyVersion: 1,
		ValidUntil: now.Add(time.Hour), QuotaRemainingBytes: 100,
	}
	runtime := NewRuntime(NewState())
	runtime.ReplaceUsers(now.Add(time.Hour), []User{user})
	session := openRuntimeSessionForTest(t, runtime, user)
	reservation := session.ReserveTraffic(service.RuntimeTrafficUplink, 0, 10)
	runtime.ReplaceUsers(now.Add(time.Hour), nil)
	session.Close()
	if len(runtime.ledgers) != 1 {
		t.Fatalf("ledger with unsettled reservation was removed: %d", len(runtime.ledgers))
	}
	reservation.Refund()
	if len(runtime.ledgers) != 0 {
		t.Fatalf("inactive settled ledger count = %d, want 0", len(runtime.ledgers))
	}
}

func openRuntimeSessionForTest(t *testing.T, runtime *Runtime, user User) *runtimeSession {
	t.Helper()
	opened, ok := runtime.OpenRuntimeSession(
		"tcp", credentialLabel(user), netip.MustParseAddrPort("192.0.2.1:1234"), conn.Addr{},
	)
	if !ok {
		t.Fatal("runtime session was rejected")
	}
	session, ok := opened.(*runtimeSession)
	if !ok {
		t.Fatalf("runtime session type = %T", opened)
	}
	return session
}
