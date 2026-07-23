package flyskynode

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConfigValidation(t *testing.T) {
	t.Parallel()

	config := testConfig(t)
	if err := config.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	config.SyncStatePath = config.SnapshotPath
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "distinct") {
		t.Fatalf("overlapping state path error = %v", err)
	}
}

func TestLoadConfigRejectsInvalidBoolean(t *testing.T) {
	t.Setenv("FLYSKY_CONTROL_PLANE_URL", "https://panel.example")
	t.Setenv("ENABLE_UDP", "sometimes")
	if err := LoadConfig().Validate(); err == nil || !strings.Contains(err.Error(), "ENABLE_UDP") {
		t.Fatalf("invalid boolean error = %v", err)
	}
}

func testConfig(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	return Config{
		ControlPlaneURL:       "https://panel.example",
		EnrollmentTokenPath:   filepath.Join(dir, "enrollment"),
		MachineCredentialPath: filepath.Join(dir, "machine.json"),
		SnapshotPath:          filepath.Join(dir, "snapshot.json"),
		SyncStatePath:         filepath.Join(dir, "sync.json"),
		ReportOutboxPath:      filepath.Join(dir, "reports.json"),
		CredentialPath:        filepath.Join(dir, "users.json"),
		ListenHost:            "127.0.0.1", EnableTCP: true, EnableUDP: true,
		ChangePollInterval: 15 * time.Second, HeartbeatInterval: 30 * time.Second,
		UsageReportInterval: 30 * time.Second, AliveIPReportInterval: time.Minute,
		SnapshotRefreshBefore: 10 * time.Minute, CredentialRotateBefore: 2 * time.Hour,
		UDPMTU: 1496, UDPRelayBatchSize: 8, UDPServerBatchSize: 64, UDPSendQueueSize: 1024,
		UDPNATTimeout: time.Minute, UDPMaxSessions: 2048, UDPMaxSessionsPerUser: 128,
		TCPMaxHandshakes: 1024, TCPMaxConnectionsPerUser: 800,
		TCPTrafficFlushInterval: 30 * time.Second,
	}
}
