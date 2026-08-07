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
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
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

func TestWaitForManagerDrainIsBounded(t *testing.T) {
	t.Parallel()
	result := make(chan bool, 1)
	started := time.Now()
	if ok, err := waitForManagerDrain(result, 20*time.Millisecond); ok || !errors.Is(err, ErrRuntimeDrainTimeout) {
		t.Fatalf("waitForManagerDrain() = %v, %v", ok, err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("bounded drain took %s", elapsed)
	}
	// The buffered production channel remains safe if the manager finishes
	// after the supervisor has already returned on timeout.
	result <- true
}

func TestWaitForManagerDrainReturnsManagerResult(t *testing.T) {
	t.Parallel()
	result := make(chan bool, 1)
	result <- true
	ok, err := waitForManagerDrain(result, time.Second)
	if err != nil || !ok {
		t.Fatalf("waitForManagerDrain() = %v, %v", ok, err)
	}
}

func TestShutdownRuntimeOrdersDrainBeforeDurableCaptureAndFlush(t *testing.T) {
	t.Parallel()
	var steps []string
	captureErr := errors.New("capture failed")
	result := shutdownRuntime(
		func() { steps = append(steps, "cancel") },
		func() (bool, error) { steps = append(steps, "drain"); return true, nil },
		func() { steps = append(steps, "close") },
		func() error { steps = append(steps, "capture"); return captureErr },
		func() error { steps = append(steps, "flush"); return nil },
	)
	if got, want := strings.Join(steps, ","), "cancel,drain,close,capture,flush"; got != want {
		t.Fatalf("shutdown order = %s, want %s", got, want)
	}
	if !result.managerOK || result.drainErr != nil || !errors.Is(result.captureErr, captureErr) || result.flushErr != nil {
		t.Fatalf("shutdown result = %+v", result)
	}
}

func TestShutdownRuntimeStillCapturesAfterBoundedDrainTimeout(t *testing.T) {
	t.Parallel()
	var captured, flushed bool
	result := shutdownRuntime(
		func() {},
		func() (bool, error) { return false, ErrRuntimeDrainTimeout },
		func() {},
		func() error { captured = true; return nil },
		func() error { flushed = true; return nil },
	)
	if !errors.Is(result.drainErr, ErrRuntimeDrainTimeout) || !captured || !flushed {
		t.Fatalf("timeout shutdown result=%+v captured=%v flushed=%v", result, captured, flushed)
	}
}

func TestCaptureUsageReportPropagatesPersistenceFailureAndRestoresTraffic(t *testing.T) {
	t.Parallel()
	outbox, err := newReportOutbox(filepath.Join(t.TempDir(), "reports.json"))
	if err != nil {
		t.Fatal(err)
	}
	persistErr := errors.New("fsync failed")
	outbox.write = func(string, []byte) error { return persistErr }
	state := NewState()
	state.AddTraffic(reportTestUserID(0), 1, 7, 11)
	windowStart := time.Now().UTC().Add(-time.Minute)
	originalWindowStart := windowStart
	applied := AppliedSnapshot{Wire: flyskyapi.Snapshot{
		ConfigVersion: "config-42",
		Node:          flyskyapi.SnapshotNode{NodeID: reportTestNodeID},
	}}
	if err := captureUsageReport(state, outbox, applied, &windowStart, zap.NewNop()); !errors.Is(err, persistErr) {
		t.Fatalf("captureUsageReport() error = %v", err)
	}
	if !windowStart.Equal(originalWindowStart) {
		t.Fatalf("window start advanced after failed capture: %s", windowStart)
	}
	deltas := state.SnapshotTraffic()
	if len(deltas) != 1 || deltas[0].UploadBytes != 7 || deltas[0].DownloadBytes != 11 {
		t.Fatalf("traffic was not restored after failed capture: %+v", deltas)
	}
}

func TestCaptureAliveIPReportPropagatesPersistenceFailure(t *testing.T) {
	t.Parallel()
	outbox, err := newReportOutbox(filepath.Join(t.TempDir(), "reports.json"))
	if err != nil {
		t.Fatal(err)
	}
	persistErr := errors.New("fsync failed")
	outbox.write = func(string, []byte) error { return persistErr }
	applied := AppliedSnapshot{Wire: flyskyapi.Snapshot{
		Node: flyskyapi.SnapshotNode{NodeID: reportTestNodeID},
	}}
	if err := captureAliveIPReport(NewState(), outbox, applied, time.Minute, zap.NewNop()); !errors.Is(err, persistErr) {
		t.Fatalf("captureAliveIPReport() error = %v", err)
	}
}

func TestLogReportFlushFailureIncludesReconciliationCounts(t *testing.T) {
	t.Parallel()
	core, observed := observer.New(zapcore.WarnLevel)
	outbox := &reportOutbox{state: persistedReportOutbox{
		UsageReports:          make([]flyskyapi.UsageReport, 1),
		AliveIPReports:        make([]flyskyapi.AliveIPReport, 2),
		UsageReconciliation:   make([]usageReportReconciliation, 3),
		AliveIPReconciliation: make([]aliveIPReportReconciliation, 4),
	}}
	logReportFlushFailure(zap.New(core), "flush failed", outbox, errors.New("boom"))
	if observed.FilterField(zap.Int("usagePending", 1)).Len() != 1 ||
		observed.FilterField(zap.Int("aliveIPPending", 2)).Len() != 1 ||
		observed.FilterField(zap.Int("usageReconciliation", 3)).Len() != 1 ||
		observed.FilterField(zap.Int("aliveIPReconciliation", 4)).Len() != 1 {
		t.Fatalf("flush log fields = %+v", observed.All())
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
		Limits: flyskyapi.CapabilitiesLimits{UsageReportMaxItems: 10000, UsageReportMaxBytes: 4 << 20},
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

func TestCapabilityReportAdvertisesNodeDNSAndInjectedVersion(t *testing.T) {
	previous := buildVersion
	buildVersion = "v3.1"
	t.Cleanup(func() { buildVersion = previous })

	report := capabilityReport(testConfig(t))
	if report.Version != "3.1" {
		t.Fatalf("capability version = %q, want 3.1", report.Version)
	}
	if !containsString(report.Features, "node_dns_v1") {
		t.Fatalf("capability features = %v, missing node_dns_v1", report.Features)
	}
}

func TestUsageLimitsFromCapabilities(t *testing.T) {
	t.Parallel()
	capabilities := flyskyapi.Capabilities{Limits: flyskyapi.CapabilitiesLimits{
		UsageReportMaxItems: 2, UsageReportMaxBytes: 4096,
	}}
	limits, err := usageLimitsFromCapabilities(capabilities)
	if err != nil || limits.MaxItems != 2 || limits.MaxEncodedBytes != 4096 {
		t.Fatalf("usageLimitsFromCapabilities() = %+v, %v", limits, err)
	}
	capabilities.Limits.UsageReportMaxItems = 0
	if _, err := usageLimitsFromCapabilities(capabilities); err == nil {
		t.Fatal("zero negotiated item limit was accepted")
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
	if credentials := managed.Credentials(); len(credentials) != 1 || credentials[0].Name != credentialLabel(applied.Users[0]) {
		t.Fatalf("initial managed credentials = %+v", credentials)
	}
	syncer.SetCredentialReloader(managed)
	if _, err := syncer.PollChanges(context.Background(), "token"); err != nil {
		t.Fatal(err)
	}
	credentials := managed.Credentials()
	updated, ok := syncer.Current()
	if !ok {
		t.Fatal("updated snapshot is unavailable")
	}
	if len(credentials) != 1 || credentials[0].Name != credentialLabel(updated.Users[0]) || !bytes.Equal(credentials[0].UPSK, bytes.Repeat([]byte{0x33}, keyLen)) {
		t.Fatalf("reloaded managed credentials = %+v", credentials)
	}
}
