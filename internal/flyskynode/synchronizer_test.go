package flyskynode

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/internal/flyskyapi"
)

type fakeControlPlane struct {
	snapshot    flyskyapi.Snapshot
	snapshotErr error
	changes     flyskyapi.Changes
	changesErr  error
}

func (fake *fakeControlPlane) Snapshot(context.Context, string) (flyskyapi.Snapshot, error) {
	return fake.snapshot, fake.snapshotErr
}

func (fake *fakeControlPlane) Changes(context.Context, string, string) (flyskyapi.Changes, error) {
	return fake.changes, fake.changesErr
}

type fakeReloader struct {
	calls int
	err   error
}

func (fake *fakeReloader) LoadFromFile() error {
	fake.calls++
	return fake.err
}

func TestSynchronizerInstallsSnapshotAndAppliesUUIDChanges(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	initial := validSnapshot(now)
	user1 := initial.Users[0].UserID
	user2 := "30000000-0000-4000-8000-000000000003"
	user2Wire := flyskyapi.SnapshotUser{
		UserID: user2, CredentialVersion: 2, UserKey: encodedKey(0x33),
		ValidUntil: now.Add(2 * time.Hour), QuotaRemainingBytes: 2048, PolicyVersion: 3,
	}
	upsertPayload, err := json.Marshal(user2Wire)
	if err != nil {
		t.Fatal(err)
	}
	revokePayload, err := json.Marshal(map[string]string{"user_id": user1})
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeControlPlane{snapshot: initial, changes: flyskyapi.Changes{
		ServingGeneration: initial.ServingGeneration,
		Changes: []flyskyapi.Change{
			{Sequence: 11, Operation: "upsert_user", ResourceID: user2, ResourceVersion: 3, Payload: upsertPayload},
			{Sequence: 12, Operation: "revoke_user", ResourceID: user1, ResourceVersion: 4, Payload: revokePayload},
		},
		NextCursor: "cursor-12",
	}}
	dir := t.TempDir()
	credentialPath := filepath.Join(dir, "users.json")
	snapshotPath := filepath.Join(dir, "snapshot.json")
	syncPath := filepath.Join(dir, "sync.json")
	runtime := NewRuntime(NewState())
	runtime.now = func() time.Time { return now }
	syncer := NewSynchronizer(fake, runtime, credentialPath, snapshotPath, syncPath)
	syncer.now = func() time.Time { return now }

	applied, err := syncer.FetchAndInstallSnapshot(context.Background(), "machine-token", initial.Node.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied.Users) != 1 || applied.Users[0].ID != user1 {
		t.Fatalf("initial applied users = %+v", applied.Users)
	}
	assertPrivateRegularFile(t, credentialPath)
	assertPrivateRegularFile(t, snapshotPath)
	assertPrivateRegularFile(t, syncPath)
	var credentials map[string][]byte
	credentialData, err := os.ReadFile(credentialPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(credentialData, &credentials); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(credentials[credentialLabel(applied.Users[0])], bytes.Repeat([]byte{0x22}, keyLen)) {
		t.Fatalf("credential file = %+v", credentials)
	}

	reloader := &fakeReloader{}
	syncer.SetCredentialReloader(reloader)
	updated, err := syncer.PollChanges(context.Background(), "machine-token")
	if err != nil {
		t.Fatal(err)
	}
	if updated.Wire.Cursor != "cursor-12" || len(updated.Users) != 1 || updated.Users[0].ID != user2 {
		t.Fatalf("updated snapshot = %+v", updated)
	}
	if reloader.calls != 1 {
		t.Fatalf("credential reload calls = %d", reloader.calls)
	}
	source := netip.MustParseAddrPort("192.0.2.10:12345")
	if runtime.Accept("tcp", credentialLabel(applied.Users[0]), source, conn.Addr{}) {
		t.Fatal("revoked user remained active")
	}
	if !runtime.Accept("tcp", credentialLabel(updated.Users[0]), source, conn.Addr{}) {
		t.Fatal("upserted user was not activated")
	}
	persisted, err := flyskyapi.LoadSnapshot(snapshotPath)
	if err != nil || persisted.Cursor != "cursor-12" {
		t.Fatalf("persisted snapshot = %+v, %v", persisted, err)
	}
	syncState, err := flyskyapi.LoadSyncState(syncPath)
	if err != nil || syncState.AppliedServingGeneration != initial.ServingGeneration || syncState.Cursor != "cursor-12" {
		t.Fatalf("sync state = %+v, %v", syncState, err)
	}
}

func TestSynchronizerDoesNotAdvanceCursorForRestartChanges(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	initial := validSnapshot(now)
	fake := &fakeControlPlane{snapshot: initial, changes: flyskyapi.Changes{
		ServingGeneration: initial.ServingGeneration,
		Changes: []flyskyapi.Change{{
			Sequence: 11, Operation: "rotate_secret", ResourceID: initial.Node.NodeID,
			ResourceVersion: 2, Payload: json.RawMessage(`{"server_secret_version":2}`),
		}},
		NextCursor: "cursor-11",
	}}
	dir := t.TempDir()
	syncer := NewSynchronizer(fake, NewRuntime(NewState()), filepath.Join(dir, "users.json"), filepath.Join(dir, "snapshot.json"), filepath.Join(dir, "sync.json"))
	syncer.now = func() time.Time { return now }
	if _, err := syncer.FetchAndInstallSnapshot(context.Background(), "token", initial.Node.NodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := syncer.PollChanges(context.Background(), "token"); !errors.Is(err, ErrRestartRequired) {
		t.Fatalf("PollChanges() error = %v", err)
	}
	current, ok := syncer.Current()
	if !ok || current.Wire.Cursor != initial.Cursor {
		t.Fatalf("current snapshot = %+v", current)
	}
	persisted, err := flyskyapi.LoadSyncState(filepath.Join(dir, "sync.json"))
	if err != nil || persisted.Cursor != initial.Cursor {
		t.Fatalf("persisted cursor = %+v, %v", persisted, err)
	}
}

func TestSynchronizerRejectsUnsafeSnapshots(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*flyskyapi.Snapshot)
	}{
		{name: "missing serving generation", mutate: func(snapshot *flyskyapi.Snapshot) { snapshot.ServingGeneration = "" }},
		{name: "invalid serving generation", mutate: func(snapshot *flyskyapi.Snapshot) { snapshot.ServingGeneration = "not-a-uuid" }},
		{name: "wrong node", mutate: func(snapshot *flyskyapi.Snapshot) { snapshot.Node.NodeID = "30000000-0000-4000-8000-000000000003" }},
		{name: "bad key", mutate: func(snapshot *flyskyapi.Snapshot) { snapshot.Users[0].UserKey = "not-base64" }},
		{name: "expired", mutate: func(snapshot *flyskyapi.Snapshot) { snapshot.ValidUntil = now.Add(-time.Minute) }},
		{name: "missing resource fences", mutate: func(snapshot *flyskyapi.Snapshot) { snapshot.ResourceVersions = nil }},
		{name: "missing user resource fence", mutate: func(snapshot *flyskyapi.Snapshot) {
			delete(snapshot.ResourceVersions, snapshot.Users[0].UserID)
		}},
		{name: "mismatched user resource fence", mutate: func(snapshot *flyskyapi.Snapshot) {
			snapshot.Users[0].PolicyVersion++
		}},
		{name: "duplicate key", mutate: func(snapshot *flyskyapi.Snapshot) {
			other := snapshot.Users[0]
			other.UserID = "30000000-0000-4000-8000-000000000003"
			snapshot.Users = append(snapshot.Users, other)
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			snapshot := validSnapshot(now)
			test.mutate(&snapshot)
			_, err := validateSnapshot(snapshot, "10000000-0000-4000-8000-000000000001", now)
			if err == nil {
				t.Fatal("unsafe snapshot was accepted")
			}
		})
	}
}

func TestSynchronizerFiltersExpiredAndZeroQuotaUsers(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	snapshot := validSnapshot(now)
	expired := snapshot.Users[0]
	expired.UserID = "30000000-0000-4000-8000-000000000003"
	expired.UserKey = encodedKey(0x33)
	expired.ValidUntil = now.Add(-time.Minute)
	zeroQuota := snapshot.Users[0]
	zeroQuota.UserID = "40000000-0000-4000-8000-000000000004"
	zeroQuota.UserKey = encodedKey(0x44)
	zeroQuota.QuotaRemainingBytes = 0
	unlimited := zeroQuota
	unlimited.UserID = "50000000-0000-4000-8000-000000000005"
	unlimited.UserKey = encodedKey(0x55)
	unlimited.Unlimited = true
	snapshot.Users = append(snapshot.Users, expired, zeroQuota, unlimited)
	snapshot.ResourceVersions[expired.UserID] = 1
	snapshot.ResourceVersions[zeroQuota.UserID] = 1
	snapshot.ResourceVersions[unlimited.UserID] = 1
	applied, err := validateSnapshot(snapshot, snapshot.Node.NodeID, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied.Users) != 2 || !applied.Users[1].Unlimited {
		t.Fatalf("active users = %+v", applied.Users)
	}
}

func TestApplyChangesFencesStaleAndEqualUserMutations(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	initial := validSnapshot(now)
	userID := initial.Users[0].UserID
	newer := initial.Users[0]
	newer.CredentialVersion = 2
	newer.PolicyVersion = 2
	newer.UserKey = encodedKey(0x33)
	newest := newer
	newest.CredentialVersion = 3
	newest.PolicyVersion = 3
	newest.UserKey = encodedKey(0x55)
	old := initial.Users[0]
	old.UserKey = encodedKey(0x44)

	next, changed, err := applyChanges(initial, flyskyapi.Changes{
		ServingGeneration: initial.ServingGeneration,
		Changes: []flyskyapi.Change{
			changeWithUser(t, 11, 2, newer),
			changeWithUser(t, 12, 1, old),
			changeWithRevoke(t, 13, userID, 1),
			changeWithRevoke(t, 14, userID, 2),
			changeWithUser(t, 15, 3, newest),
		},
		NextCursor: "cursor-15",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || next.Cursor != "cursor-15" {
		t.Fatalf("apply result changed=%v cursor=%q", changed, next.Cursor)
	}
	if len(next.Users) != 1 || next.Users[0].CredentialVersion != 3 || next.Users[0].UserKey != newest.UserKey {
		t.Fatalf("final user = %+v, want newest upsert", next.Users)
	}
	if next.ResourceVersions[userID] != 3 {
		t.Fatalf("resource version = %d, want 3", next.ResourceVersions[userID])
	}
}

func TestApplyChangesOnlyAdvancesCursorForStaleMutations(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	initial := validSnapshot(now)
	userID := initial.Users[0].UserID
	stale := initial.Users[0]
	stale.UserKey = encodedKey(0x66)
	next, changed, err := applyChanges(initial, flyskyapi.Changes{
		ServingGeneration: initial.ServingGeneration,
		Changes: []flyskyapi.Change{
			changeWithUser(t, 11, 1, stale),
			changeWithRevoke(t, 12, userID, 1),
		},
		NextCursor: "cursor-12",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || next.Cursor != "cursor-12" {
		t.Fatalf("apply result changed=%v cursor=%q", changed, next.Cursor)
	}
	if len(next.Users) != 1 || next.Users[0].UserKey != initial.Users[0].UserKey {
		t.Fatalf("stale change altered users: %+v", next.Users)
	}
	if next.ResourceVersions[userID] != 1 {
		t.Fatalf("resource version = %d, want 1", next.ResourceVersions[userID])
	}
}

func TestApplyChangesRejectsPolicyResourceVersionMismatch(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	initial := validSnapshot(now)
	mismatched := initial.Users[0]
	mismatched.PolicyVersion = 3
	mismatched.CredentialVersion = 2
	mismatched.UserKey = encodedKey(0x33)
	_, _, err := applyChanges(initial, flyskyapi.Changes{
		ServingGeneration: initial.ServingGeneration,
		Changes:           []flyskyapi.Change{changeWithUser(t, 11, 2, mismatched)}, NextCursor: "cursor-11",
	}, now)
	if err == nil || !strings.Contains(err.Error(), "policy version") {
		t.Fatalf("mismatched policy/resource version error = %v", err)
	}
}

func TestApplyChangesRejectsIncrementalCountLimitPlusOne(t *testing.T) {
	t.Parallel()

	initial := validSnapshot(time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC))
	_, _, err := applyChanges(initial, flyskyapi.Changes{
		ServingGeneration: initial.ServingGeneration,
		Changes:           make([]flyskyapi.Change, flyskyapi.MaxIncrementalChanges+1), NextCursor: "cursor-too-many",
	}, time.Now().UTC())
	if err == nil {
		t.Fatal("changes response with record count limit+1 was accepted")
	}
}

func TestApplyChangesRejectsDifferentOrMissingServingGeneration(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	initial := validSnapshot(now)
	for _, generation := range []string{"", "not-a-uuid", "80000000-0000-4000-8000-000000000008"} {
		_, _, err := applyChanges(initial, flyskyapi.Changes{
			ServingGeneration: generation,
			NextCursor:        "cursor-11",
		}, now)
		if !errors.Is(err, ErrServingGenerationChanged) {
			t.Fatalf("generation %q error = %v, want ErrServingGenerationChanged", generation, err)
		}
	}
}

func TestApplyChangesRequiresExactStopServingGeneration(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	initial := validSnapshot(now)
	payload, err := json.Marshal(map[string]string{"serving_generation": initial.ServingGeneration})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = applyChanges(initial, flyskyapi.Changes{
		ServingGeneration: initial.ServingGeneration,
		Changes: []flyskyapi.Change{
			{
				Sequence: 10, Operation: "upsert_user", ResourceID: initial.Users[0].UserID,
				ResourceVersion: 2, Payload: json.RawMessage(`{"malformed":true}`),
			},
			{
				Sequence: 11, Operation: "stop_serving", ResourceID: initial.Node.NodeID,
				ResourceVersion: 2, Payload: payload,
			},
		},
		NextCursor: "cursor-11",
	}, now)
	var stopRequest *StopServingRequestError
	if !errors.As(err, &stopRequest) || stopRequest.ServingGeneration != initial.ServingGeneration {
		t.Fatalf("stop-serving error = %#v", err)
	}

	wrongPayload, err := json.Marshal(map[string]string{"serving_generation": "80000000-0000-4000-8000-000000000008"})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = applyChanges(initial, flyskyapi.Changes{
		ServingGeneration: initial.ServingGeneration,
		Changes: []flyskyapi.Change{{
			Sequence: 11, Operation: "stop_serving", ResourceID: initial.Node.NodeID,
			ResourceVersion: 2, Payload: wrongPayload,
		}},
		NextCursor: "cursor-11",
	}, now)
	if err == nil || errors.Is(err, ErrStopServingRequested) {
		t.Fatalf("mismatched stop-serving generation error = %v", err)
	}
}

func TestSynchronizerStopServingBarrierAndCompletionAreDurable(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	initial := validSnapshot(now)
	payload, err := json.Marshal(map[string]string{"serving_generation": initial.ServingGeneration})
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeControlPlane{snapshot: initial, changes: flyskyapi.Changes{
		ServingGeneration: initial.ServingGeneration,
		Changes: []flyskyapi.Change{{
			Sequence: 11, Operation: "stop_serving", ResourceID: initial.Node.NodeID,
			ResourceVersion: 2, Payload: payload,
		}},
		NextCursor: "cursor-11",
	}}
	dir := t.TempDir()
	credentialPath := filepath.Join(dir, "users.json")
	snapshotPath := filepath.Join(dir, "snapshot.json")
	syncPath := filepath.Join(dir, "sync.json")
	runtime := NewRuntime(NewState())
	runtime.now = func() time.Time { return now }
	syncer := NewSynchronizer(fake, runtime, credentialPath, snapshotPath, syncPath)
	syncer.now = func() time.Time { return now }
	applied, err := syncer.FetchAndInstallSnapshot(context.Background(), "token", initial.Node.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := syncer.PollChanges(context.Background(), "token"); !errors.Is(err, ErrStopServingRequested) {
		t.Fatalf("PollChanges() error = %v", err)
	}
	barrier, exists, err := syncer.LoadStopServingState(initial.Node.NodeID)
	if err != nil || !exists || barrier.Phase != "requested" || barrier.ServingGeneration != initial.ServingGeneration {
		t.Fatalf("requested barrier = %+v, exists=%v err=%v", barrier, exists, err)
	}
	if err := syncer.CompleteStopServing(initial.Node.NodeID, initial.ServingGeneration); err != nil {
		t.Fatal(err)
	}
	barrier, exists, err = syncer.LoadStopServingState(initial.Node.NodeID)
	if err != nil || !exists || barrier.Phase != "stopped" {
		t.Fatalf("stopped barrier = %+v, exists=%v err=%v", barrier, exists, err)
	}
	for _, path := range []string{credentialPath, snapshotPath, syncPath} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stop-serving cleanup left %s: %v", path, err)
		}
	}
	if _, ok := syncer.Current(); ok {
		t.Fatal("stopped synchronizer retained a reportable applied snapshot")
	}
	source := netip.MustParseAddrPort("192.0.2.10:12345")
	if runtime.Accept("tcp", credentialLabel(applied.Users[0]), source, conn.Addr{}) {
		t.Fatal("stopped runtime accepted an old credential")
	}
}

func TestStopServingFullSnapshotDoesNotActivateOrAdvanceCursor(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	initial := validSnapshot(now)
	dir := t.TempDir()
	credentialPath := filepath.Join(dir, "users.json")
	snapshotPath := filepath.Join(dir, "snapshot.json")
	syncPath := filepath.Join(dir, "sync.json")
	syncer := NewSynchronizer(nil, NewRuntime(NewState()), credentialPath, snapshotPath, syncPath)
	syncer.now = func() time.Time { return now }
	if _, err := syncer.InstallSnapshot(initial, initial.Node.NodeID); err != nil {
		t.Fatal(err)
	}
	retiring := initial
	retiring.ConfigVersion = "99"
	retiring.Cursor = "cursor-after-stop"
	retiring.StopServingGeneration = initial.ServingGeneration
	if _, err := syncer.InstallSnapshot(retiring, initial.Node.NodeID); !errors.Is(err, ErrStopServingRequested) {
		t.Fatalf("retiring snapshot error = %v", err)
	}
	state, err := flyskyapi.LoadSyncState(syncPath)
	if err != nil || state.Cursor != initial.Cursor || state.ConfigVersion != initial.ConfigVersion {
		t.Fatalf("retiring snapshot advanced durable ACK: %+v, %v", state, err)
	}
	cached, err := flyskyapi.LoadSnapshot(snapshotPath)
	if err != nil || cached.Cursor != initial.Cursor || cached.StopServingGeneration != "" {
		t.Fatalf("retiring snapshot replaced active cache: %+v, %v", cached, err)
	}
	barrier, exists, err := syncer.LoadStopServingState(initial.Node.NodeID)
	if err != nil || !exists || barrier.Phase != "requested" || barrier.ServingGeneration != initial.ServingGeneration {
		t.Fatalf("retiring snapshot barrier = %+v, exists=%v err=%v", barrier, exists, err)
	}
}

func TestSynchronizerStopServingCleanupFailureWithholdsStoppedAck(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	initial := validSnapshot(now)
	dir := t.TempDir()
	syncer := NewSynchronizer(nil, NewRuntime(NewState()), filepath.Join(dir, "users.json"), filepath.Join(dir, "snapshot.json"), filepath.Join(dir, "sync.json"))
	syncer.now = func() time.Time { return now }
	if _, err := syncer.InstallSnapshot(initial, initial.Node.NodeID); err != nil {
		t.Fatal(err)
	}
	if err := syncer.persistStopServingRequested(initial.Node.NodeID, initial.ServingGeneration); err != nil {
		t.Fatal(err)
	}
	syncer.SetCredentialReloader(&fakeReloader{err: errors.New("empty credential reload failed")})
	if err := syncer.CompleteStopServing(initial.Node.NodeID, initial.ServingGeneration); err == nil {
		t.Fatal("cleanup failure unexpectedly produced a stopped acknowledgement")
	}
	barrier, exists, err := syncer.LoadStopServingState(initial.Node.NodeID)
	if err != nil || !exists || barrier.Phase != "requested" {
		t.Fatalf("cleanup failure barrier = %+v, exists=%v err=%v", barrier, exists, err)
	}
}

func TestReactivationRequiresAndAcknowledgesANewServingGeneration(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	initial := validSnapshot(now)
	dir := t.TempDir()
	syncer := NewSynchronizer(nil, NewRuntime(NewState()), filepath.Join(dir, "users.json"), filepath.Join(dir, "snapshot.json"), filepath.Join(dir, "sync.json"))
	syncer.now = func() time.Time { return now }
	if _, err := syncer.InstallSnapshot(initial, initial.Node.NodeID); err != nil {
		t.Fatal(err)
	}
	if err := syncer.persistStopServingRequested(initial.Node.NodeID, initial.ServingGeneration); err != nil {
		t.Fatal(err)
	}
	if err := syncer.CompleteStopServing(initial.Node.NodeID, initial.ServingGeneration); err != nil {
		t.Fatal(err)
	}
	if _, err := syncer.InstallSnapshot(initial, initial.Node.NodeID); !errors.Is(err, ErrStopServingRequested) {
		t.Fatalf("historical generation crossed stop barrier: %v", err)
	}

	reactivated := initial
	reactivated.ServingGeneration = "80000000-0000-4000-8000-000000000008"
	reactivated.ConfigVersion = "20"
	reactivated.Cursor = "cursor-20"
	if _, err := syncer.InstallSnapshot(reactivated, initial.Node.NodeID); err != nil {
		t.Fatal(err)
	}
	state, err := flyskyapi.LoadSyncState(syncer.syncStatePath)
	if err != nil || state.AppliedServingGeneration != reactivated.ServingGeneration || state.Cursor != reactivated.Cursor {
		t.Fatalf("reactivated acknowledgement = %+v, %v", state, err)
	}
	if _, exists, err := syncer.LoadStopServingState(initial.Node.NodeID); err != nil || exists {
		t.Fatalf("obsolete stop barrier survived reactivation: exists=%v err=%v", exists, err)
	}
}

func TestFreshSnapshotTombstoneRejectsStaleChanges(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	snapshot := validSnapshot(now)
	user := snapshot.Users[0]
	userID := user.UserID
	snapshot.Users = nil
	snapshot.ResourceVersions[userID] = 11
	applied, err := validateSnapshot(snapshot, snapshot.Node.NodeID, now)
	if err != nil {
		t.Fatal(err)
	}
	stale := user
	stale.CredentialVersion = 2
	stale.PolicyVersion = 2
	stale.UserKey = encodedKey(0x44)
	next, changed, err := applyChanges(applied.Wire, flyskyapi.Changes{
		ServingGeneration: applied.Wire.ServingGeneration,
		Changes: []flyskyapi.Change{
			changeWithUser(t, 11, 10, stale),
			changeWithRevoke(t, 12, userID, 11),
		},
		NextCursor: "cursor-12",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || next.Cursor != "cursor-12" || len(next.Users) != 0 || next.ResourceVersions[userID] != 11 {
		t.Fatalf("stale changes crossed fresh tombstone: %+v", next)
	}

	newer := stale
	newer.CredentialVersion = 3
	newer.UserKey = encodedKey(0x55)
	newer.PolicyVersion = 12
	next, _, err = applyChanges(next, flyskyapi.Changes{
		ServingGeneration: next.ServingGeneration,
		Changes:           []flyskyapi.Change{changeWithUser(t, 13, 12, newer)}, NextCursor: "cursor-13",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Users) != 1 || next.Users[0].UserKey != newer.UserKey || next.ResourceVersions[userID] != 12 {
		t.Fatalf("newer upsert did not cross tombstone: %+v", next)
	}
}

func TestSynchronizerPersistsRevokeTombstoneAcrossRestart(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	initial := validSnapshot(now)
	initial.ResourceVersions[initial.Users[0].UserID] = 10
	initial.Users[0].PolicyVersion = 10
	user := initial.Users[0]
	userID := user.UserID
	fake := &fakeControlPlane{snapshot: initial, changes: flyskyapi.Changes{
		ServingGeneration: initial.ServingGeneration,
		Changes:           []flyskyapi.Change{changeWithRevoke(t, 11, userID, 11)}, NextCursor: "cursor-11",
	}}
	dir := t.TempDir()
	credentialPath := filepath.Join(dir, "users.json")
	snapshotPath := filepath.Join(dir, "snapshot.json")
	syncPath := filepath.Join(dir, "sync.json")
	syncer := NewSynchronizer(fake, NewRuntime(NewState()), credentialPath, snapshotPath, syncPath)
	syncer.now = func() time.Time { return now }
	if _, err := syncer.FetchAndInstallSnapshot(context.Background(), "token", initial.Node.NodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := syncer.PollChanges(context.Background(), "token"); err != nil {
		t.Fatal(err)
	}

	persistedState, err := flyskyapi.LoadSyncState(syncPath)
	if err != nil {
		t.Fatal(err)
	}
	if persistedState.SchemaVersion != 3 || persistedState.AppliedServingGeneration != initial.ServingGeneration || persistedState.ResourceVersions[userID] != 11 {
		t.Fatalf("persisted state = %+v", persistedState)
	}
	persistedSnapshot, err := flyskyapi.LoadSnapshot(snapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(persistedSnapshot.Users) != 0 || persistedSnapshot.ResourceVersions[userID] != 11 {
		t.Fatalf("persisted snapshot lost tombstone: %+v", persistedSnapshot)
	}

	stale := user
	stale.CredentialVersion = 2
	stale.PolicyVersion = 2
	stale.UserKey = encodedKey(0x44)
	fake.changes = flyskyapi.Changes{
		ServingGeneration: initial.ServingGeneration,
		Changes:           []flyskyapi.Change{changeWithUser(t, 12, 10, stale)}, NextCursor: "cursor-12",
	}
	restartedRuntime := NewRuntime(NewState())
	restartedRuntime.now = func() time.Time { return now }
	restarted := NewSynchronizer(fake, restartedRuntime, credentialPath, snapshotPath, syncPath)
	restarted.now = func() time.Time { return now }
	loaded, err := restarted.LoadCachedSnapshot(initial.Node.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Users) != 0 {
		t.Fatalf("cached tombstone restored a user: %+v", loaded.Users)
	}
	updated, err := restarted.PollChanges(context.Background(), "token")
	if err != nil {
		t.Fatal(err)
	}
	if updated.Wire.Cursor != "cursor-12" || len(updated.Users) != 0 || updated.Wire.ResourceVersions[userID] != 11 {
		t.Fatalf("stale upsert crossed restarted tombstone: %+v", updated)
	}

	newer := stale
	newer.CredentialVersion = 3
	newer.PolicyVersion = 12
	newer.UserKey = encodedKey(0x55)
	fake.changes = flyskyapi.Changes{
		ServingGeneration: initial.ServingGeneration,
		Changes:           []flyskyapi.Change{changeWithUser(t, 13, 12, newer)}, NextCursor: "cursor-13",
	}
	updated, err = restarted.PollChanges(context.Background(), "token")
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Users) != 1 || updated.Users[0].CredentialVersion != 3 || updated.Wire.ResourceVersions[userID] != 12 {
		t.Fatalf("newer upsert was not installed: %+v", updated)
	}
	persistedState, err = flyskyapi.LoadSyncState(syncPath)
	if err != nil || persistedState.ResourceVersions[userID] != 12 || persistedState.Cursor != "cursor-13" {
		t.Fatalf("newer upsert fence was not persisted: %+v, %v", persistedState, err)
	}
	persistedSnapshot, err = flyskyapi.LoadSnapshot(snapshotPath)
	if err != nil || len(persistedSnapshot.Users) != 1 || persistedSnapshot.ResourceVersions[userID] != 12 {
		t.Fatalf("newer upsert snapshot was not persisted: %+v, %v", persistedSnapshot, err)
	}
}

func TestSynchronizerDurableFenceClosesStateBeforeSnapshotCrashWindow(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	oldSnapshot := validSnapshot(now)
	userID := oldSnapshot.Users[0].UserID
	oldSnapshot.ResourceVersions[userID] = 10
	oldSnapshot.Users[0].PolicyVersion = 10
	dir := t.TempDir()
	snapshotPath := filepath.Join(dir, "snapshot.json")
	syncPath := filepath.Join(dir, "sync.json")
	if err := flyskyapi.SaveSnapshot(snapshotPath, oldSnapshot); err != nil {
		t.Fatal(err)
	}
	// Simulate a process dying after the new revoke fence is durable but
	// before the old cached snapshot has been replaced.
	if err := flyskyapi.SaveSyncState(syncPath, flyskyapi.SyncState{
		NodeID: oldSnapshot.Node.NodeID, SchemaVersion: 3,
		AppliedServingGeneration: oldSnapshot.ServingGeneration,
		ConfigVersion:            oldSnapshot.ConfigVersion, Cursor: oldSnapshot.Cursor,
		SnapshotValidUntil: oldSnapshot.ValidUntil, UpdatedAt: now,
		ResourceVersions: map[string]int64{userID: 11},
	}); err != nil {
		t.Fatal(err)
	}
	runtime := NewRuntime(NewState())
	runtime.now = func() time.Time { return now }
	syncer := NewSynchronizer(&fakeControlPlane{}, runtime, filepath.Join(dir, "users.json"), snapshotPath, syncPath)
	syncer.now = func() time.Time { return now }
	loaded, err := syncer.LoadCachedSnapshot(oldSnapshot.Node.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Users) != 0 || len(loaded.Wire.Users) != 0 || loaded.Wire.ResourceVersions[userID] != 11 {
		t.Fatalf("old cached user survived a newer durable fence: %+v", loaded)
	}
}

func TestSnapshotResponseLossDoesNotAdvanceAppliedAcknowledgement(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	initial := validSnapshot(now)
	fake := &fakeControlPlane{snapshot: initial}
	dir := t.TempDir()
	syncer := NewSynchronizer(fake, NewRuntime(NewState()), filepath.Join(dir, "users.json"), filepath.Join(dir, "snapshot.json"), filepath.Join(dir, "sync.json"))
	syncer.now = func() time.Time { return now }
	if _, err := syncer.FetchAndInstallSnapshot(context.Background(), "token", initial.Node.NodeID); err != nil {
		t.Fatal(err)
	}

	next := initial
	next.ServingGeneration = "80000000-0000-4000-8000-000000000008"
	next.ConfigVersion = "11"
	next.Cursor = "cursor-11"
	fake.snapshot = next
	fake.snapshotErr = errors.New("snapshot response lost")
	if _, err := syncer.FetchAndInstallSnapshot(context.Background(), "token", initial.Node.NodeID); err == nil {
		t.Fatal("lost snapshot response unexpectedly installed")
	}
	state, err := flyskyapi.LoadSyncState(filepath.Join(dir, "sync.json"))
	if err != nil {
		t.Fatal(err)
	}
	if state.AppliedServingGeneration != initial.ServingGeneration || state.Cursor != initial.Cursor {
		t.Fatalf("lost response advanced applied acknowledgement: %+v", state)
	}
	current, ok := syncer.Current()
	if !ok || current.Wire.ServingGeneration != initial.ServingGeneration || current.Wire.Cursor != initial.Cursor {
		t.Fatalf("lost response changed current snapshot: %+v, %v", current, ok)
	}
	fake.snapshotErr = nil
	installed, err := syncer.FetchAndInstallSnapshot(context.Background(), "token", initial.Node.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	state, err = flyskyapi.LoadSyncState(filepath.Join(dir, "sync.json"))
	if err != nil || installed.Wire.ServingGeneration != next.ServingGeneration ||
		state.AppliedServingGeneration != next.ServingGeneration || state.Cursor != next.Cursor {
		t.Fatalf("received generation was not acknowledged after install: installed=%+v state=%+v err=%v", installed.Wire, state, err)
	}
}

func TestAppliedGenerationPersistsOnlyAfterFinalCommitAndSurvivesRestart(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	initial := validSnapshot(now)
	dir := t.TempDir()
	credentialPath := filepath.Join(dir, "users.json")
	snapshotPath := filepath.Join(dir, "snapshot.json")
	syncPath := filepath.Join(dir, "sync.json")
	syncer := NewSynchronizer(&fakeControlPlane{snapshot: initial}, NewRuntime(NewState()), credentialPath, snapshotPath, syncPath)
	syncer.now = func() time.Time { return now }
	if _, err := syncer.InstallSnapshot(initial, initial.Node.NodeID); err != nil {
		t.Fatal(err)
	}
	state, err := flyskyapi.LoadSyncState(syncPath)
	if err != nil {
		t.Fatal(err)
	}
	if state.SchemaVersion != 3 || state.AppliedServingGeneration != initial.ServingGeneration || state.Cursor != initial.Cursor {
		t.Fatalf("initial applied acknowledgement = %+v", state)
	}

	restarted := NewSynchronizer(nil, NewRuntime(NewState()), credentialPath, snapshotPath, syncPath)
	restarted.now = func() time.Time { return now }
	loaded, err := restarted.LoadCachedSnapshot(initial.Node.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Wire.ServingGeneration != initial.ServingGeneration || loaded.Wire.Cursor != initial.Cursor {
		t.Fatalf("restart restored wrong applied acknowledgement: %+v", loaded.Wire)
	}
	restartedState, err := flyskyapi.LoadSyncState(syncPath)
	if err != nil || restartedState.AppliedServingGeneration != initial.ServingGeneration || restartedState.Cursor != initial.Cursor {
		t.Fatalf("restart durable acknowledgement = %+v, %v", restartedState, err)
	}
}

func TestGenerationChangeFinalStateFailureDoesNotInheritNewAcknowledgement(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	initial := validSnapshot(now)
	dir := t.TempDir()
	credentialPath := filepath.Join(dir, "users.json")
	snapshotPath := filepath.Join(dir, "snapshot.json")
	syncPath := filepath.Join(dir, "sync.json")
	syncer := NewSynchronizer(nil, NewRuntime(NewState()), credentialPath, snapshotPath, syncPath)
	syncer.now = func() time.Time { return now }
	if _, err := syncer.InstallSnapshot(initial, initial.Node.NodeID); err != nil {
		t.Fatal(err)
	}

	next := initial
	next.ServingGeneration = "80000000-0000-4000-8000-000000000008"
	next.ConfigVersion = "11"
	next.Cursor = "cursor-11"
	writeCalls := 0
	syncer.saveSyncState = func(path string, state flyskyapi.SyncState) error {
		writeCalls++
		if writeCalls == 2 {
			return errors.New("final acknowledgement fsync failed")
		}
		return flyskyapi.SaveSyncState(path, state)
	}
	if _, err := syncer.InstallSnapshot(next, initial.Node.NodeID); !errors.Is(err, ErrSynchronizationUnsafe) {
		t.Fatalf("generation install error = %v, want ErrSynchronizationUnsafe", err)
	}
	if writeCalls != 2 {
		t.Fatalf("sync-state writes = %d, want 2", writeCalls)
	}
	state, err := flyskyapi.LoadSyncState(syncPath)
	if err != nil {
		t.Fatal(err)
	}
	if state.AppliedServingGeneration != initial.ServingGeneration || state.Cursor != initial.Cursor {
		t.Fatalf("failed generation inherited new acknowledgement: %+v", state)
	}
	if _, ok := syncer.Current(); ok {
		t.Fatal("failed generation remained reportable as a current snapshot")
	}
	if _, err := os.Stat(snapshotPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed generation left a restartable cached snapshot: %v", err)
	}
	restarted := NewSynchronizer(nil, NewRuntime(NewState()), credentialPath, snapshotPath, syncPath)
	if _, err := restarted.LoadCachedSnapshot(initial.Node.NodeID); err == nil {
		t.Fatal("restart inherited an acknowledgement from the failed generation install")
	}
}

func TestSynchronizerCommitFailuresFailClosed(t *testing.T) {
	now := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	initial := validSnapshot(now)
	user := initial.Users[0]
	nextWire, _, err := applyChanges(initial, flyskyapi.Changes{
		ServingGeneration: initial.ServingGeneration,
		Changes:           []flyskyapi.Change{changeWithRevoke(t, 11, user.UserID, 2)}, NextCursor: "cursor-11",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	next, err := validateSnapshot(nextWire, initial.Node.NodeID, now)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		configure func(t *testing.T, syncer *Synchronizer, dir string)
	}{
		{name: "sync state", configure: func(t *testing.T, syncer *Synchronizer, dir string) {
			if err := os.Mkdir(syncer.syncStatePath, 0700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "credentials", configure: func(t *testing.T, syncer *Synchronizer, dir string) {
			if err := os.Mkdir(syncer.credentialPath, 0700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "credential reload", configure: func(t *testing.T, syncer *Synchronizer, dir string) {
			syncer.SetCredentialReloader(&fakeReloader{err: errors.New("reload failed")})
		}},
		{name: "snapshot", configure: func(t *testing.T, syncer *Synchronizer, dir string) {
			if err := os.Mkdir(syncer.snapshotPath, 0700); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			runtime := NewRuntime(NewState())
			runtime.now = func() time.Time { return now }
			runtime.ReplaceUsers(initial.ValidUntil, []User{{
				ID: user.UserID, CredentialVersion: user.CredentialVersion, Key: bytes.Repeat([]byte{0x22}, keyLen),
				ValidUntil: user.ValidUntil, QuotaRemainingBytes: user.QuotaRemainingBytes, PolicyVersion: user.PolicyVersion,
			}})
			syncer := NewSynchronizer(nil, runtime, filepath.Join(dir, "users.json"), filepath.Join(dir, "snapshot.json"), filepath.Join(dir, "sync.json"))
			syncer.now = func() time.Time { return now }
			test.configure(t, syncer, dir)
			if err := syncer.commit(next); !errors.Is(err, ErrSynchronizationUnsafe) {
				t.Fatalf("commit error = %v, want ErrSynchronizationUnsafe", err)
			} else if err == nil {
				t.Fatal("commit unexpectedly succeeded")
			}
			source := netip.MustParseAddrPort("192.0.2.10:12345")
			old := User{ID: user.UserID, CredentialVersion: user.CredentialVersion, PolicyVersion: user.PolicyVersion}
			if runtime.Accept("tcp", credentialLabel(old), source, conn.Addr{}) {
				t.Fatal("old credential remained authorized after a partial commit")
			}
			if state, err := flyskyapi.LoadSyncState(syncer.syncStatePath); err == nil && state.AppliedServingGeneration != "" {
				t.Fatalf("partial commit persisted an applied acknowledgement: %+v", state)
			}
		})
	}
}

func TestSynchronizerSyncStateFailureInvalidatesCachedAuthorization(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	initial := validSnapshot(now)
	user := initial.Users[0]
	nextWire, _, err := applyChanges(initial, flyskyapi.Changes{
		ServingGeneration: initial.ServingGeneration,
		Changes:           []flyskyapi.Change{changeWithRevoke(t, 11, user.UserID, 2)}, NextCursor: "cursor-11",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	next, err := validateSnapshot(nextWire, initial.Node.NodeID, now)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	credentialPath := filepath.Join(dir, "users.json")
	snapshotPath := filepath.Join(dir, "snapshot.json")
	syncPath := filepath.Join(dir, "sync.json")
	if err := flyskyapi.SaveSnapshot(snapshotPath, initial); err != nil {
		t.Fatal(err)
	}
	if err := writeCredentials(credentialPath, []User{{
		ID: user.UserID, CredentialVersion: user.CredentialVersion, Key: bytes.Repeat([]byte{0x22}, keyLen),
		ValidUntil: user.ValidUntil, QuotaRemainingBytes: user.QuotaRemainingBytes, PolicyVersion: user.PolicyVersion,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(syncPath, 0700); err != nil {
		t.Fatal(err)
	}
	runtime := NewRuntime(NewState())
	runtime.now = func() time.Time { return now }
	runtime.ReplaceUsers(initial.ValidUntil, []User{{
		ID: user.UserID, CredentialVersion: user.CredentialVersion, Key: bytes.Repeat([]byte{0x22}, keyLen),
		ValidUntil: user.ValidUntil, QuotaRemainingBytes: user.QuotaRemainingBytes, PolicyVersion: user.PolicyVersion,
	}})
	syncer := NewSynchronizer(nil, runtime, credentialPath, snapshotPath, syncPath)
	syncer.now = func() time.Time { return now }
	if err := syncer.commit(next); !errors.Is(err, ErrSynchronizationUnsafe) {
		t.Fatalf("commit error = %v, want ErrSynchronizationUnsafe", err)
	}
	if _, err := os.Stat(snapshotPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cached snapshot remains after fail-closed commit: %v", err)
	}
	if _, err := os.Stat(credentialPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("credential cache remains after fail-closed commit: %v", err)
	}
	restarted := NewSynchronizer(nil, NewRuntime(NewState()), credentialPath, snapshotPath, syncPath)
	if _, err := restarted.LoadCachedSnapshot(initial.Node.NodeID); err == nil {
		t.Fatal("offline restart restored an authorization after sync-state persistence failed")
	}
}

func changeWithUser(t *testing.T, sequence, resourceVersion int64, user flyskyapi.SnapshotUser) flyskyapi.Change {
	t.Helper()
	payload, err := json.Marshal(user)
	if err != nil {
		t.Fatal(err)
	}
	return flyskyapi.Change{
		Sequence: sequence, Operation: "upsert_user", ResourceID: user.UserID,
		ResourceVersion: resourceVersion, Payload: payload,
	}
}

func changeWithRevoke(t *testing.T, sequence int64, userID string, resourceVersion int64) flyskyapi.Change {
	t.Helper()
	payload, err := json.Marshal(map[string]string{"user_id": userID})
	if err != nil {
		t.Fatal(err)
	}
	return flyskyapi.Change{
		Sequence: sequence, Operation: "revoke_user", ResourceID: userID,
		ResourceVersion: resourceVersion, Payload: payload,
	}
}

func validSnapshot(now time.Time) flyskyapi.Snapshot {
	return flyskyapi.Snapshot{
		SchemaVersion: 1, ServingGeneration: "90000000-0000-4000-8000-000000000009",
		ConfigVersion: "10", Cursor: "cursor-10",
		GeneratedAt: now.Add(-time.Minute), ValidUntil: now.Add(time.Hour),
		Node: flyskyapi.SnapshotNode{
			NodeID: "10000000-0000-4000-8000-000000000001", Protocol: "ss2022", Method: method,
			ListenPort: 443, ServerSecretVersion: 1, ServerKey: encodedKey(0x11),
		},
		Users: []flyskyapi.SnapshotUser{{
			UserID: "20000000-0000-4000-8000-000000000002", CredentialVersion: 1,
			UserKey: encodedKey(0x22), ValidUntil: now.Add(2 * time.Hour),
			QuotaRemainingBytes: 1024, PolicyVersion: 1,
		}},
		ResourceVersions: map[string]int64{"20000000-0000-4000-8000-000000000002": 1},
	}
}

func encodedKey(value byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{value}, keyLen))
}

func assertPrivateRegularFile(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatalf("%s mode = %v", path, info.Mode())
	}
}
