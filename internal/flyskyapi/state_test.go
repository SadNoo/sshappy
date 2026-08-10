package flyskyapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
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
		NodeID: "10000000-0000-4000-8000-000000000001", SchemaVersion: 3,
		AppliedServingGeneration: "90000000-0000-4000-8000-000000000009",
		ConfigVersion:            "42", Cursor: "cursor-42", SnapshotValidUntil: now.Add(time.Hour), UpdatedAt: now,
		ResourceVersions: map[string]int64{
			"20000000-0000-4000-8000-000000000002": 7,
			"30000000-0000-4000-8000-000000000003": 9,
		},
	}
	path := filepath.Join(t.TempDir(), "sync.json")
	if err := SaveSyncState(path, state); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadSyncState(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded, state) {
		t.Fatalf("loaded state = %+v, want %+v", loaded, state)
	}
}

func TestSyncStateV1RemainsReadable(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "sync-v1.json")
	legacy := []byte(`{"node_id":"10000000-0000-4000-8000-000000000001","schema_version":1,"config_version":"42","cursor":"cursor-42","snapshot_valid_until":"2026-07-23T02:02:03Z","updated_at":"2026-07-23T01:02:03Z"}`)
	if err := os.WriteFile(path, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadSyncState(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.SchemaVersion != 1 || len(loaded.ResourceVersions) != 0 {
		t.Fatalf("loaded legacy state = %+v", loaded)
	}
}

func TestSyncStateV2RemainsReadableWithoutAppliedGeneration(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "sync-v2.json")
	legacy := []byte(`{"node_id":"10000000-0000-4000-8000-000000000001","schema_version":2,"config_version":"42","cursor":"cursor-42","snapshot_valid_until":"2026-07-23T02:02:03Z","updated_at":"2026-07-23T01:02:03Z","resource_versions":{"20000000-0000-4000-8000-000000000002":7}}`)
	if err := os.WriteFile(path, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadSyncState(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.SchemaVersion != 2 || loaded.AppliedServingGeneration != "" || loaded.ResourceVersions["20000000-0000-4000-8000-000000000002"] != 7 {
		t.Fatalf("loaded legacy v2 state = %+v", loaded)
	}
}

func TestSyncStateV3AllowsFenceOnlyButRejectsPartialAppliedAck(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	fenceOnly := SyncState{
		NodeID: "10000000-0000-4000-8000-000000000001", SchemaVersion: 3, UpdatedAt: now,
		ResourceVersions: map[string]int64{"20000000-0000-4000-8000-000000000002": 7},
	}
	if err := SaveSyncState(filepath.Join(t.TempDir(), "fence-only.json"), fenceOnly); err != nil {
		t.Fatalf("fence-only v3 state rejected: %v", err)
	}
	partial := fenceOnly
	partial.AppliedServingGeneration = "90000000-0000-4000-8000-000000000009"
	if err := SaveSyncState(filepath.Join(t.TempDir(), "partial.json"), partial); err == nil {
		t.Fatal("partial applied acknowledgement was accepted")
	}
}

func TestStopServingStateRoundTrip(t *testing.T) {
	t.Parallel()

	state := StopServingState{
		NodeID:            "10000000-0000-4000-8000-000000000001",
		ServingGeneration: "90000000-0000-4000-8000-000000000009",
		Phase:             "requested", UpdatedAt: time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC),
	}
	path := filepath.Join(t.TempDir(), "stop-serving.json")
	if err := SaveStopServingState(path, state); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadStopServingState(path)
	if err != nil || loaded != state {
		t.Fatalf("loaded stop-serving state = %+v, %v", loaded, err)
	}
	state.Phase = "unknown"
	if err := SaveStopServingState(path, state); err == nil {
		t.Fatal("invalid stop-serving phase was accepted")
	}
}

func TestSyncStateResourceFenceMapMayExceedLegacy64KiBLimit(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	versions := make(map[string]int64, 5000)
	for index := 0; index < 5000; index++ {
		versions[fmt.Sprintf("20000000-0000-4000-8000-%012d", index)] = int64(index + 1)
	}
	state := SyncState{
		NodeID: "10000000-0000-4000-8000-000000000001", SchemaVersion: 2,
		ConfigVersion: "42", Cursor: "cursor-42", SnapshotValidUntil: now.Add(time.Hour), UpdatedAt: now,
		ResourceVersions: versions,
	}
	path := filepath.Join(t.TempDir(), "large-sync.json")
	if err := SaveSyncState(path, state); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() <= 64<<10 {
		t.Fatalf("large synchronization state size = %d, want > legacy 64KiB limit", info.Size())
	}
	loaded, err := LoadSyncState(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded.ResourceVersions, versions) {
		t.Fatalf("loaded %d resource versions, want %d", len(loaded.ResourceVersions), len(versions))
	}
}

func TestThirtyThousandUsersFitBoundedSnapshotAndFenceState(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	const userCount = 30000
	users := make([]SnapshotUser, 0, userCount)
	versions := make(map[string]int64, userCount)
	key := strings.Repeat("A", 43) + "="
	for index := 0; index < userCount; index++ {
		userID := fmt.Sprintf("20000000-0000-4000-8000-%012d", index)
		version := int64(index + 1)
		users = append(users, SnapshotUser{
			UserID: userID, CredentialVersion: version, UserKey: key,
			ValidUntil: now.AddDate(1, 0, 0), QuotaRemainingBytes: 10 << 40, PolicyVersion: version,
		})
		versions[userID] = version
	}
	snapshot := Snapshot{
		SchemaVersion: 1, ServingGeneration: "90000000-0000-4000-8000-000000000009",
		ConfigVersion: "30000", Cursor: "cursor-30000", GeneratedAt: now, ValidUntil: now.Add(time.Hour),
		Node: SnapshotNode{
			NodeID: "10000000-0000-4000-8000-000000000001", Protocol: "ss2022",
			Method: "2022-blake3-aes-256-gcm", ListenPort: 443, ServerSecretVersion: 1, ServerKey: key,
		},
		Users: users, ResourceVersions: versions,
	}
	snapshotJSON, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshotJSON)+1 > maxSnapshotStateBytes || len(snapshotJSON) > defaultMaxSnapshotBodyBytes {
		t.Fatalf("30k snapshot size = %d, exceeds state=%d or HTTP=%d", len(snapshotJSON), maxSnapshotStateBytes, defaultMaxSnapshotBodyBytes)
	}
	state := SyncState{
		NodeID: snapshot.Node.NodeID, SchemaVersion: 3, AppliedServingGeneration: snapshot.ServingGeneration,
		ConfigVersion: snapshot.ConfigVersion,
		Cursor:        snapshot.Cursor, SnapshotValidUntil: snapshot.ValidUntil, UpdatedAt: now,
		ResourceVersions: versions,
	}
	stateJSON, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if len(stateJSON)+1 > maxSyncStateBytes {
		t.Fatalf("30k synchronization state size = %d, exceeds %d", len(stateJSON), maxSyncStateBytes)
	}
	t.Logf("30k encoded sizes: snapshot=%d bytes, sync-state=%d bytes", len(snapshotJSON), len(stateJSON))
}

func TestStateIOHonorsExactAndLimitPlusOneBoundaries(t *testing.T) {
	t.Parallel()

	const limit = 128
	dir := t.TempDir()
	exactPath := filepath.Join(dir, "exact.json")
	if err := writeState(exactPath, strings.Repeat("x", limit-3), limit); err != nil {
		t.Fatalf("write exact-limit state: %v", err)
	}
	if info, err := os.Stat(exactPath); err != nil || info.Size() != limit {
		t.Fatalf("exact-limit state size = %v, %v", info, err)
	}
	if err := writeState(filepath.Join(dir, "over.json"), strings.Repeat("x", limit-2), limit); err == nil {
		t.Fatal("limit+1 state write was accepted")
	}

	readExactPath := filepath.Join(dir, "read-exact.json")
	readOverPath := filepath.Join(dir, "read-over.json")
	if err := os.WriteFile(readExactPath, []byte(`"`+strings.Repeat("x", limit-2)+`"`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(readOverPath, []byte(`"`+strings.Repeat("x", limit-1)+`"`), 0600); err != nil {
		t.Fatal(err)
	}
	var exact string
	if err := readState(readExactPath, &exact, limit); err != nil || len(exact) != limit-2 {
		t.Fatalf("read exact-limit state = %d chars, %v", len(exact), err)
	}
	if err := readState(readOverPath, new(string), limit); err == nil {
		t.Fatal("limit+1 state read was accepted")
	}
}

func TestSnapshotStateRejectsUserCountLimitPlusOne(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	snapshot := Snapshot{
		SchemaVersion: 1, ServingGeneration: "90000000-0000-4000-8000-000000000009",
		ConfigVersion: "42", Cursor: "cursor-42", GeneratedAt: now, ValidUntil: now.Add(time.Hour),
		Node:  SnapshotNode{NodeID: "10000000-0000-4000-8000-000000000001", ServerKey: strings.Repeat("A", 43) + "="},
		Users: make([]SnapshotUser, MaxSnapshotUsers+1), ResourceVersions: map[string]int64{},
	}
	if err := validateSnapshotState(snapshot); err == nil {
		t.Fatal("snapshot with user count limit+1 was accepted")
	}
}

func TestSnapshotStateRoundTrip(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	snapshot := Snapshot{
		SchemaVersion: 1, ServingGeneration: "90000000-0000-4000-8000-000000000009",
		ConfigVersion: "42", Cursor: "cursor-42", GeneratedAt: now,
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
