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
		Changes: []flyskyapi.Change{
			{Sequence: 11, Operation: "upsert_user", ResourceID: user2, ResourceVersion: 2, Payload: upsertPayload},
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
	if err != nil || syncState.Cursor != "cursor-12" {
		t.Fatalf("sync state = %+v, %v", syncState, err)
	}
}

func TestSynchronizerDoesNotAdvanceCursorForRestartChanges(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	initial := validSnapshot(now)
	fake := &fakeControlPlane{snapshot: initial, changes: flyskyapi.Changes{
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
		{name: "wrong node", mutate: func(snapshot *flyskyapi.Snapshot) { snapshot.Node.NodeID = "30000000-0000-4000-8000-000000000003" }},
		{name: "bad key", mutate: func(snapshot *flyskyapi.Snapshot) { snapshot.Users[0].UserKey = "not-base64" }},
		{name: "expired", mutate: func(snapshot *flyskyapi.Snapshot) { snapshot.ValidUntil = now.Add(-time.Minute) }},
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
	applied, err := validateSnapshot(snapshot, snapshot.Node.NodeID, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied.Users) != 2 || !applied.Users[1].Unlimited {
		t.Fatalf("active users = %+v", applied.Users)
	}
}

func validSnapshot(now time.Time) flyskyapi.Snapshot {
	return flyskyapi.Snapshot{
		SchemaVersion: 1, ConfigVersion: "10", Cursor: "cursor-10",
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
