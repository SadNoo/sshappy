package flyskyapi

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMachineCredentialStateRoundTrip(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "nested", "credential.json")
	credential := MachineCredential{
		NodeID: "10000000-0000-4000-8000-000000000001", AccessToken: "fnode_" + strings.Repeat("a", 43),
		TokenType: "Bearer", ExpiresAt: time.Date(2026, time.July, 24, 1, 2, 3, 0, time.UTC),
	}
	if err := SaveMachineCredential(path, credential); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("credential permissions = %v, want 0600", info.Mode().Perm())
	}
	loaded, err := LoadMachineCredential(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != credential {
		t.Fatalf("loaded credential = %+v, want %+v", loaded, credential)
	}
}

func TestSyncStateRoundTrip(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	state := SyncState{
		NodeID: "10000000-0000-4000-8000-000000000001", SchemaVersion: 1,
		ConfigVersion: "42", Cursor: "cursor-42", SnapshotValidUntil: now.Add(time.Hour), UpdatedAt: now,
	}
	path := filepath.Join(t.TempDir(), "sync.json")
	if err := SaveSyncState(path, state); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadSyncState(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != state {
		t.Fatalf("loaded state = %+v, want %+v", loaded, state)
	}
}

func TestSnapshotStateRoundTrip(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	snapshot := Snapshot{
		SchemaVersion: 1, ConfigVersion: "42", Cursor: "cursor-42", GeneratedAt: now,
		ValidUntil: now.Add(time.Hour),
		Node: SnapshotNode{
			NodeID: "10000000-0000-4000-8000-000000000001", Protocol: "ss2022",
			Method: "2022-blake3-aes-256-gcm", ListenPort: 443, ServerSecretVersion: 1,
			ServerKey: "c2VydmVyLWtleQ==",
		},
	}
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := SaveSnapshot(path, snapshot); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadSnapshot(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Node.NodeID != snapshot.Node.NodeID || loaded.Cursor != snapshot.Cursor {
		t.Fatalf("loaded snapshot = %+v, want %+v", loaded, snapshot)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("snapshot permissions = %v, want 0600", info.Mode().Perm())
	}
}

func TestStateRejectsLoosePermissionsAndNonRegularFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "credential.json")
	data := []byte(`{"node_id":"node","access_token":"token","token_type":"Bearer","expires_at":"2026-07-24T01:02:03Z"}`)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMachineCredential(path); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("loose permissions error = %v", err)
	}

	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "credential-link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMachineCredential(link); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlink error = %v", err)
	}
}

func TestStateRejectsUnknownFieldsAndInvalidValues(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "credential.json")
	if err := os.WriteFile(path, []byte(`{"node_id":"node","access_token":"token","token_type":"Bearer","expires_at":"2026-07-24T01:02:03Z","unexpected":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMachineCredential(path); err == nil {
		t.Fatal("state with unknown field was accepted")
	}
	if err := SaveMachineCredential(path, MachineCredential{}); err == nil {
		t.Fatal("invalid credential was accepted")
	}
	if err := SaveSyncState(path, SyncState{}); err == nil {
		t.Fatal("invalid sync state was accepted")
	}
}

func TestLoadMissingStatePreservesNotExist(t *testing.T) {
	t.Parallel()

	_, err := LoadMachineCredential(filepath.Join(t.TempDir(), "missing.json"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("LoadMachineCredential() error = %v", err)
	}
}
