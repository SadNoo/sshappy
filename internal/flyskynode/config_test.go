package flyskynode

import (
	"net/netip"
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

func TestLoadConfigEnablesSafeOuterUDPFragmentationDefaults(t *testing.T) {
	t.Setenv("FLYSKY_CONTROL_PLANE_URL", "https://panel.example")
	config := LoadConfig()
	if config.UDPMTU != 1600 || !config.UDPOuterFragmentation {
		t.Fatalf("UDP transport defaults = mtu %d, fragmentation %v", config.UDPMTU, config.UDPOuterFragmentation)
	}
}

func TestLoadConfigParsesProtectedEgressPrefixes(t *testing.T) {
	t.Setenv("FLYSKY_CONTROL_PLANE_URL", "https://panel.example")
	t.Setenv("FLYSKY_PROTECTED_EGRESS_PREFIXES", " 8.8.8.8, 1.1.1.0/24,8.8.8.8/32,::ffff:9.9.9.9 ")
	config := LoadConfig()
	if err := config.Validate(); err != nil {
		t.Fatalf("valid protected prefixes rejected: %v", err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("8.8.8.8/32"),
		netip.MustParsePrefix("1.1.1.0/24"),
		netip.MustParsePrefix("9.9.9.9/32"),
	}
	if len(config.ProtectedEgressPrefixes) != len(want) {
		t.Fatalf("protected prefixes = %v, want %v", config.ProtectedEgressPrefixes, want)
	}
	for index := range want {
		if config.ProtectedEgressPrefixes[index] != want[index] {
			t.Fatalf("protected prefix %d = %v, want %v", index, config.ProtectedEgressPrefixes[index], want[index])
		}
	}
}

func TestLoadConfigRejectsInvalidProtectedEgressPrefixes(t *testing.T) {
	t.Setenv("FLYSKY_CONTROL_PLANE_URL", "https://panel.example")
	for _, value := range []string{"not-an-ip", "8.8.8.8,,1.1.1.1", "::ffff:8.8.8.8/80"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("FLYSKY_PROTECTED_EGRESS_PREFIXES", value)
			if err := LoadConfig().Validate(); err == nil || !strings.Contains(err.Error(), "FLYSKY_PROTECTED_EGRESS_PREFIXES") {
				t.Fatalf("invalid protected prefix error = %v", err)
			}
		})
	}
}

func TestLoadConfigRequiresProtectedEgressPrefix(t *testing.T) {
	t.Setenv("FLYSKY_CONTROL_PLANE_URL", "https://panel.example")
	t.Setenv("FLYSKY_PROTECTED_EGRESS_PREFIXES", "")
	if err := LoadConfig().Validate(); err == nil || !strings.Contains(err.Error(), "must include the node public address") {
		t.Fatalf("missing protected prefix error = %v", err)
	}
}

func TestConfigRejectsInvalidProtectedEgressPrefixValue(t *testing.T) {
	config := testConfig(t)
	config.ProtectedEgressPrefixes = []netip.Prefix{{}}
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "FLYSKY_PROTECTED_EGRESS_PREFIXES") {
		t.Fatalf("invalid typed protected prefix error = %v", err)
	}
}

func TestConfigRejectsUnboundedShutdownDrain(t *testing.T) {
	config := testConfig(t)
	config.ShutdownDrainTimeout = 0
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "FLYSKY_SHUTDOWN_DRAIN_SECONDS") {
		t.Fatalf("zero shutdown drain error = %v", err)
	}
	config.ShutdownDrainTimeout = 121 * time.Second
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "FLYSKY_SHUTDOWN_DRAIN_SECONDS") {
		t.Fatalf("oversized shutdown drain error = %v", err)
	}
}

func testConfig(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	return Config{
		ControlPlaneURL: "https://panel.example",
		ProtectedEgressPrefixes: []netip.Prefix{
			netip.MustParsePrefix("203.0.113.10/32"),
		},
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
		UDPMTU: 1600, UDPOuterFragmentation: true,
		UDPRelayBatchSize: 8, UDPServerBatchSize: 64, UDPSendQueueSize: 1024,
		UDPNATTimeout: time.Minute, UDPMaxSessions: 2048, UDPMaxSessionsPerUser: 128,
		TCPMaxHandshakes: 1024, TCPMaxConnectionsPerUser: 800,
		TCPTrafficFlushInterval: 30 * time.Second,
		ShutdownDrainTimeout:    30 * time.Second,
	}
}
