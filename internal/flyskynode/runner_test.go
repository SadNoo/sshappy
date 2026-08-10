package flyskynode

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
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

type startupSnapshotSourceStub struct {
	fetchErr    error
	cachedCalls int
}

func (source *startupSnapshotSourceStub) FetchAndInstallSnapshot(
	context.Context,
	string,
	string,
) (AppliedSnapshot, error) {
	return AppliedSnapshot{}, source.fetchErr
}

func (source *startupSnapshotSourceStub) LoadCachedSnapshot(string) (AppliedSnapshot, error) {
	source.cachedCalls++
	return AppliedSnapshot{}, errors.New("cached snapshot must not be loaded")
}

func TestUnsafeStartupSnapshotFailureNeverFallsBackToCache(t *testing.T) {
	t.Parallel()

	for _, fatalErr := range []error{
		ErrSynchronizationUnsafe,
		ErrRestartRequired,
		&StopServingRequestError{ServingGeneration: "90000000-0000-4000-8000-000000000009"},
	} {
		source := &startupSnapshotSourceStub{fetchErr: fatalErr}
		_, err := loadStartupSnapshot(context.Background(), source, "token", "node-id", zap.NewNop())
		if !errors.Is(err, fatalErr) {
			t.Fatalf("loadStartupSnapshot() error = %v, want %v", err, fatalErr)
		}
		if source.cachedCalls != 0 {
			t.Fatalf("fatal startup error %v loaded cache %d times", fatalErr, source.cachedCalls)
		}
	}
}

func TestRunHandlesStartupStopSnapshotBeforeManagerStarts(t *testing.T) {
	now := time.Now().UTC()
	snapshot := validSnapshot(now)
	snapshot.StopServingGeneration = snapshot.ServingGeneration
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	snapshot.Node.ListenPort = occupied.Addr().(*net.TCPAddr).Port
	var snapshotCalls, statusCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/api/node/v1/capabilities":
			_ = json.NewEncoder(response).Encode(map[string]any{
				"ok": true,
				"data": map[string]any{
					"api_version": "v1", "schema_versions": []int{1},
					"features": []string{
						"snapshot_v1", "cursor_changes_v1", "status_report_v1", "usage_batch_v1",
						"alive_ip_aggregate_v1", "resource_version_fence_v1",
						"serving_generation_ack_v1", "stop_serving_ack_v1",
					},
					"protocols": map[string]any{"ss2022": map[string]any{
						"methods": []string{method}, "tcp": true, "udp": true, "single_port_multi_user": true,
					}},
					"limits": map[string]any{"usage_report_max_bytes": 4 << 20, "usage_report_max_items": 10000},
				},
			})
		case "/api/node/v1/snapshot":
			snapshotCalls.Add(1)
			_ = json.NewEncoder(response).Encode(map[string]any{"ok": true, "data": snapshot})
		case "/api/node/v1/status":
			statusCalls.Add(1)
			var report flyskyapi.StatusRequest
			if err := json.NewDecoder(request.Body).Decode(&report); err != nil {
				t.Errorf("decode stopped status: %v", err)
			}
			if report.StoppedServingGeneration != snapshot.ServingGeneration || report.AppliedServingGeneration != "" {
				t.Errorf("startup stopped report = %+v", report)
			}
			_ = json.NewEncoder(response).Encode(map[string]any{
				"ok": true,
				"data": map[string]any{
					"state": "disabled", "state_version": 2, "last_seen_at": now,
					"next_heartbeat_seconds": 30, "stopped_serving_accepted": true,
				},
			})
		default:
			t.Errorf("unexpected startup request path %s", request.URL.Path)
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	config := testConfig(t)
	config.ControlPlaneURL = server.URL
	config.AllowInsecureHTTP = true
	config.EnableUDP = false
	if err := flyskyapi.SaveMachineCredential(config.MachineCredentialPath, flyskyapi.MachineCredential{
		NodeID: snapshot.Node.NodeID, AccessToken: "machine-token", TokenType: "Bearer", ExpiresAt: now.Add(24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := Run(ctx, config, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	if snapshotCalls.Load() != 1 || statusCalls.Load() != 1 {
		t.Fatalf("startup stop calls: snapshot=%d status=%d", snapshotCalls.Load(), statusCalls.Load())
	}
	stopState, err := flyskyapi.LoadStopServingState(config.SyncStatePath + ".stop-serving")
	if err != nil || stopState.Phase != "stopped" || stopState.ServingGeneration != snapshot.ServingGeneration {
		t.Fatalf("startup stop barrier = %+v, %v", stopState, err)
	}
	for _, path := range []string{config.CredentialPath, config.SnapshotPath, config.SyncStatePath} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("startup stop left runtime state %s: %v", path, err)
		}
	}
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

func TestReportStatusCarriesDurablyAppliedGenerationAndCursor(t *testing.T) {
	servingGeneration := "90000000-0000-4000-8000-000000000009"
	cursor := "cursor-42"
	var received flyskyapi.StatusRequest
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
			t.Errorf("decode status request: %v", err)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{
			"ok": true,
			"data": map[string]any{
				"state": "online", "state_version": 1, "last_seen_at": time.Now().UTC(),
				"next_heartbeat_seconds": 60,
			},
		})
	}))
	defer server.Close()
	client, err := flyskyapi.NewClient(flyskyapi.Config{BaseURL: server.URL, AllowInsecureHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	config := testConfig(t)
	applied := AppliedSnapshot{Wire: flyskyapi.Snapshot{
		ServingGeneration: servingGeneration, Cursor: cursor, ValidUntil: time.Now().Add(time.Hour),
	}}
	if next := reportStatus(context.Background(), client, config, "machine-token", applied, zap.NewNop()); next != time.Minute {
		t.Fatalf("next heartbeat = %s, want 1m", next)
	}
	if received.AppliedServingGeneration != servingGeneration || received.AppliedCursor != cursor {
		t.Fatalf("heartbeat applied acknowledgement = %+v", received)
	}
}

func TestStoppedServingAcknowledgementExitsOnExplicitAccepted200(t *testing.T) {
	generation := "90000000-0000-4000-8000-000000000009"
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		var report flyskyapi.StatusRequest
		if err := json.NewDecoder(request.Body).Decode(&report); err != nil {
			t.Errorf("decode stopped heartbeat: %v", err)
		}
		if report.StoppedServingGeneration != generation || report.AppliedServingGeneration != "" || report.AppliedCursor != "" {
			t.Errorf("stopped heartbeat = %+v", report)
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{
			"ok": true,
			"data": map[string]any{
				"state": "disabled", "state_version": 2, "last_seen_at": time.Now().UTC(),
				"next_heartbeat_seconds": 30, "stopped_serving_accepted": true,
			},
		})
	}))
	defer server.Close()
	client, err := flyskyapi.NewClient(flyskyapi.Config{BaseURL: server.URL, AllowInsecureHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	config := testConfig(t)
	config.HeartbeatInterval = time.Millisecond
	if err := awaitStoppedServingAcknowledgement(context.Background(), client, config, "machine-token", generation, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("accepted stopped ACK calls = %d, want 1", calls.Load())
	}
}

func TestStoppedServingAcknowledgementRecognizesLost200Terminal401(t *testing.T) {
	generation := "90000000-0000-4000-8000-000000000009"
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(response).Encode(map[string]any{
			"ok":    false,
			"error": map[string]any{"code": "NODE_STOP_SERVING_FINALIZED", "retryable": false},
			"meta":  map[string]any{"request_id": "request-finalized"},
		})
	}))
	defer server.Close()
	client, err := flyskyapi.NewClient(flyskyapi.Config{BaseURL: server.URL, AllowInsecureHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	config := testConfig(t)
	config.HeartbeatInterval = time.Millisecond
	if err := awaitStoppedServingAcknowledgement(context.Background(), client, config, "revoked-token", generation, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("terminal 401 calls = %d, want 1", calls.Load())
	}
}

func TestStoppedServingAcknowledgementDoesNotTreatMismatch403AsSuccess(t *testing.T) {
	generation := "90000000-0000-4000-8000-000000000009"
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(response).Encode(map[string]any{
			"ok":    false,
			"error": map[string]any{"code": "STOP_SERVING_GENERATION_MISMATCH", "retryable": false},
		})
	}))
	defer server.Close()
	client, err := flyskyapi.NewClient(flyskyapi.Config{BaseURL: server.URL, AllowInsecureHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	config := testConfig(t)
	config.HeartbeatInterval = time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	defer cancel()
	if err := awaitStoppedServingAcknowledgement(ctx, client, config, "machine-token", generation, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() < 2 {
		t.Fatalf("mismatch 403 was treated as terminal after %d call(s)", calls.Load())
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
			"resource_version_fence_v1", "serving_generation_ack_v1", "stop_serving_ack_v1",
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
	buildVersion = "v3.3"
	t.Cleanup(func() { buildVersion = previous })

	report := capabilityReport(testConfig(t))
	if report.Version != "3.3" {
		t.Fatalf("capability version = %q, want 3.3", report.Version)
	}
	if !containsString(report.Features, "node_dns_v1") {
		t.Fatalf("capability features = %v, missing node_dns_v1", report.Features)
	}
	if !containsString(report.Features, "fake_ip_domain_v1") {
		t.Fatalf("capability features = %v, missing fake_ip_domain_v1", report.Features)
	}
	if !containsString(report.Features, "resource_version_fence_v1") {
		t.Fatalf("capability features = %v, missing resource_version_fence_v1", report.Features)
	}
	if !containsString(report.Features, "serving_generation_ack_v1") || !containsString(report.Features, "stop_serving_ack_v1") {
		t.Fatalf("capability features = %v, missing generation/stop ACK features", report.Features)
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
		ServingGeneration: initial.ServingGeneration,
		Changes: []flyskyapi.Change{
			{Sequence: 11, Operation: "upsert_user", ResourceID: user2, ResourceVersion: 3, Payload: upsertPayload},
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
