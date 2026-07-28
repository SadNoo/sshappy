package flyskynode

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/database64128/shadowsocks-go/internal/flyskyapi"
	"github.com/database64128/shadowsocks-go/service"
	"go.uber.org/zap"
)

type enrollmentClientStub struct {
	credential flyskyapi.MachineCredential
	calls      int
	token      string
}

func (client *enrollmentClientStub) Enroll(
	_ context.Context,
	token string,
	_ flyskyapi.CapabilityReport,
) (flyskyapi.MachineCredential, error) {
	client.calls++
	client.token = token
	return client.credential, nil
}

func TestReadEnrollmentTokenRequiresPrivateRegularFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "token")
	token := "fenr_" + strings.Repeat("a", 43)
	if err := os.WriteFile(path, []byte(token+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := readEnrollmentToken(path)
	if err != nil || loaded != token {
		t.Fatalf("readEnrollmentToken() = %q, %v", loaded, err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readEnrollmentToken(path); err == nil {
		t.Fatal("world-readable enrollment token was accepted")
	}
}

func TestEnrollmentTokenReplacesExistingMachineCredential(t *testing.T) {
	t.Parallel()

	config := testConfig(t)
	oldCredential := flyskyapi.MachineCredential{
		NodeID:      "10000000-0000-4000-8000-000000000001",
		AccessToken: "old-machine-token",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	if err := flyskyapi.SaveMachineCredential(config.MachineCredentialPath, oldCredential); err != nil {
		t.Fatal(err)
	}
	token := "fenr_" + strings.Repeat("b", 43)
	if err := os.WriteFile(config.EnrollmentTokenPath, []byte(token+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	nextCredential := flyskyapi.MachineCredential{
		NodeID:      oldCredential.NodeID,
		AccessToken: "replacement-machine-token",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(2 * time.Hour),
	}
	client := &enrollmentClientStub{credential: nextCredential}

	actual, err := loadOrEnroll(
		context.Background(),
		client,
		config,
		flyskyapi.CapabilityReport{},
		zap.NewNop(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if actual.AccessToken != nextCredential.AccessToken || client.calls != 1 || client.token != token {
		t.Fatalf("loadOrEnroll() = %+v, calls = %d, token = %q", actual, client.calls, client.token)
	}
	persisted, err := flyskyapi.LoadMachineCredential(config.MachineCredentialPath)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.AccessToken != nextCredential.AccessToken {
		t.Fatalf("persisted credential = %+v", persisted)
	}
	if _, err := os.Stat(config.EnrollmentTokenPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("consumed enrollment token still exists: %v", err)
	}
}

func TestServerListenAddressSupportsIPv4AndIPv6(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"0.0.0.0":     "0.0.0.0:18443",
		"::":          "[::]:18443",
		"2001:db8::1": "[2001:db8::1]:18443",
	}
	for host, expected := range tests {
		if actual := serverListenAddress(host, 18443); actual != expected {
			t.Errorf("serverListenAddress(%q, 18443) = %q, want %q", host, actual, expected)
		}
	}
}

func TestOuterUDPPathMTUDiscovery(t *testing.T) {
	t.Parallel()

	if actual := outerUDPPathMTUDiscovery(true); actual != service.PMTUDModeDont {
		t.Fatalf("fragmentation enabled PMTUD mode = %s", actual)
	}
	if actual := outerUDPPathMTUDiscovery(false); actual != service.PMTUDModeAppDefault {
		t.Fatalf("fragmentation disabled PMTUD mode = %s", actual)
	}
}

func TestValidateCapabilities(t *testing.T) {
	t.Parallel()

	config := testConfig(t)
	capabilities := flyskyapi.Capabilities{
		APIVersion: "v1", SchemaVersions: []int{1},
		Features: []string{
			"snapshot_v1", "cursor_changes_v1", "status_report_v1", "usage_batch_v1", "alive_ip_aggregate_v1",
		},
		Protocols: map[string]flyskyapi.ProtocolCapability{
			"ss2022": {Methods: []string{method}, TCP: true, UDP: true, SinglePortMultiUser: true},
		},
	}
	if err := validateCapabilities(capabilities, config); err != nil {
		t.Fatalf("valid capabilities rejected: %v", err)
	}
	capabilities.Protocols["ss2022"] = flyskyapi.ProtocolCapability{Methods: []string{method}, TCP: true}
	if err := validateCapabilities(capabilities, config); err == nil {
		t.Fatal("incompatible capabilities were accepted")
	}
}

func TestManagedServerAtomicallyReloadsUUIDCredentials(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	initial := validSnapshot(now)
	user2 := "30000000-0000-4000-8000-000000000003"
	user2Wire := flyskyapi.SnapshotUser{
		UserID: user2, CredentialVersion: 2, UserKey: encodedKey(0x33),
		ValidUntil: now.Add(2 * time.Hour), QuotaRemainingBytes: 2048, PolicyVersion: 3,
	}
	upsertPayload, err := json.Marshal(user2Wire)
	if err != nil {
		t.Fatal(err)
	}
	revokePayload, err := json.Marshal(map[string]string{"user_id": initial.Users[0].UserID})
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeControlPlane{snapshot: initial, changes: flyskyapi.Changes{
		Changes: []flyskyapi.Change{
			{Sequence: 11, Operation: "upsert_user", ResourceID: user2, ResourceVersion: 2, Payload: upsertPayload},
			{Sequence: 12, Operation: "revoke_user", ResourceID: initial.Users[0].UserID, ResourceVersion: 3, Payload: revokePayload},
		},
		NextCursor: "cursor-12",
	}}
	config := testConfig(t)
	config.EnableUDP = false
	runtimeHooks := NewRuntime(NewState())
	runtimeHooks.now = func() time.Time { return now }
	syncer := NewSynchronizer(fake, runtimeHooks, config.CredentialPath, config.SnapshotPath, config.SyncStatePath)
	syncer.now = func() time.Time { return now }
	applied, err := syncer.FetchAndInstallSnapshot(context.Background(), "token", initial.Node.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	manager, managed, err := newManager(config, applied, runtimeHooks, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if credentials := managed.Credentials(); len(credentials) != 1 || credentials[0].Name != initial.Users[0].UserID {
		t.Fatalf("initial managed credentials = %+v", credentials)
	}
	syncer.SetCredentialReloader(managed)
	if _, err := syncer.PollChanges(context.Background(), "token"); err != nil {
		t.Fatal(err)
	}
	credentials := managed.Credentials()
	if len(credentials) != 1 || credentials[0].Name != user2 || !bytes.Equal(credentials[0].UPSK, bytes.Repeat([]byte{0x33}, keyLen)) {
		t.Fatalf("reloaded managed credentials = %+v", credentials)
	}
}
