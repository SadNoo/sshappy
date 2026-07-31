package panel

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
)

func TestRuntimePolicyAndTraffic(t *testing.T) {
	state := NewState()
	runtime := NewRuntime(state)
	runtime.ReplaceUsers([]User{{
		ID:            7,
		ForbiddenIP:   "192.0.2.0/24",
		ForbiddenPort: "25,1000-1002",
		DisconnectIP:  "198.51.100.9",
	}})
	source := netip.MustParseAddrPort("198.51.100.10:12345")
	if !runtime.Accept("udp", "7", source, conn.AddrFromIPPort(netip.MustParseAddrPort("203.0.113.1:443"))) {
		t.Fatal("allowed packet was rejected")
	}
	runtime.Observe("udp", "7", source)
	if runtime.Accept("tcp", "7", source, conn.AddrFromIPPort(netip.MustParseAddrPort("192.0.2.1:443"))) {
		t.Fatal("forbidden IP was accepted")
	}
	if runtime.Accept("tcp", "7", source, conn.AddrFromIPPort(netip.MustParseAddrPort("203.0.113.1:25"))) {
		t.Fatal("forbidden port was accepted")
	}
	if runtime.Accept("tcp", "7", netip.MustParseAddrPort("198.51.100.9:12345"), conn.AddrFromIPPort(netip.MustParseAddrPort("203.0.113.1:443"))) {
		t.Fatal("disconnected source IP was accepted")
	}

	runtime.CollectUDPSessionUplink("7", 2, 100)
	runtime.CollectUDPSessionDownlink("7", 2, 80)
	traffic := state.SnapshotTraffic()
	if len(traffic) != 1 || traffic[0].Upload != 100 || traffic[0].Download != 80 {
		t.Fatalf("traffic = %+v", traffic)
	}
	if online := state.OnlineUserCount(time.Minute); online != 1 {
		t.Fatalf("online = %d", online)
	}
}

func TestDefaultUpstreamUDPSettings(t *testing.T) {
	t.Setenv("UDP_MTU", "")
	t.Setenv("UDP_RELAY_BATCH_SIZE", "")
	t.Setenv("UDP_SERVER_RECV_BATCH_SIZE", "")
	t.Setenv("UDP_SEND_CHANNEL_CAPACITY", "")
	t.Setenv("UDP_NAT_TIMEOUT_SECONDS", "")
	t.Setenv("UDP_MAX_SESSIONS", "")
	t.Setenv("UDP_MAX_SESSIONS_PER_USER", "")
	config := LoadConfig()
	if config.UDPMTU != 1496 ||
		config.UDPRelayBatchSize != 8 ||
		config.UDPServerBatchSize != 64 ||
		config.UDPSendQueueSize != 1024 ||
		config.UDPNATTimeoutSeconds != 60 ||
		config.UDPMaxSessions != 2048 ||
		config.UDPMaxSessionsPerUser != 128 {
		t.Fatalf("unexpected UDP defaults: %+v", config)
	}
}

func TestDefaultOperationalSettings(t *testing.T) {
	t.Setenv("ENABLE_TCP", "")
	t.Setenv("ENABLE_UDP", "")
	t.Setenv("TCP_MAX_CONCURRENT_HANDSHAKES", "")
	t.Setenv("TCP_TRAFFIC_FLUSH_SECONDS", "")
	t.Setenv("TCP_MAX_ESTABLISHED_TOTAL", "")
	t.Setenv("TRAFFIC_BATCH_RETENTION_DAYS", "")
	t.Setenv("MYSQL_CONNECT_TIMEOUT_SECONDS", "")
	t.Setenv("MYSQL_IO_TIMEOUT_SECONDS", "")
	t.Setenv("RESOURCE_REPORT_SECONDS", "")
	t.Setenv("OUTBOX_MIN_FREE_BYTES", "")
	t.Setenv("AUTH_STALE_GRACE_SECONDS", "")
	config := LoadConfig()
	if !config.EnableTCP || !config.EnableUDP ||
		config.TCPMaxHandshakes != 1024 ||
		config.TCPMaxConnectionsPerUser != 800 ||
		config.TCPMaxEstablishedTotal != 0 ||
		config.TCPTrafficFlushSeconds != 30 ||
		config.TrafficBatchRetentionDays != 0 ||
		config.AuthorizationStaleSeconds != 300 ||
		config.ResourceReportSeconds != 60 ||
		config.OutboxMinFreeBytes != 256<<20 ||
		config.MySQLConnectTimeoutSeconds != 10 ||
		config.MySQLIOTimeoutSeconds != 30 {
		t.Fatalf("unexpected operational defaults: %+v", config)
	}
}

func TestMergeAliveIPsPreservesLastSeen(t *testing.T) {
	state := NewState()
	state.AddAliveIP(7, "192.0.2.1")
	oldLastSeen := time.Now().Add(-time.Hour)
	state.aliveMu.Lock()
	state.lastSeen[7] = oldLastSeen
	state.aliveMu.Unlock()

	alive := state.SnapshotAliveIPs()
	state.MergeAliveIPs(alive)
	state.aliveMu.Lock()
	got := state.lastSeen[7]
	_, restored := state.alive[7]["192.0.2.1"]
	state.aliveMu.Unlock()
	if !got.Equal(oldLastSeen) || !restored {
		t.Fatalf("merge changed lastSeen or lost IP: lastSeen=%v restored=%v", got, restored)
	}
}

func TestFailClosedWindowExpiresIndependently(t *testing.T) {
	canceled := make(chan struct{}, 1)
	window := newFailClosedWindow(20*time.Millisecond, func() { canceled <- struct{}{} })
	defer window.Close()
	cause := errors.New("database unavailable")
	age, remaining, expired := window.RecordFailure("node authorization refresh", cause, time.Now())
	if age != 0 || remaining <= 0 || expired {
		t.Fatalf("unexpected initial window: age=%v remaining=%v expired=%v", age, remaining, expired)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("fail-closed deadline did not cancel the relay independently")
	}
	select {
	case <-window.Expired():
	case <-time.After(time.Second):
		t.Fatal("fail-closed deadline did not notify the runner")
	}
	if err := window.Err(time.Now()); !errors.Is(err, cause) {
		t.Fatalf("expiration error = %v, want wrapped cause", err)
	}
}

func TestFailClosedWindowRecoversOnlySuccessfulOperation(t *testing.T) {
	canceled := make(chan struct{}, 1)
	window := newFailClosedWindow(40*time.Millisecond, func() { canceled <- struct{}{} })
	defer window.Close()
	window.RecordFailure("node authorization refresh", errors.New("node read failed"), time.Now())
	window.RecordFailure("traffic accounting", errors.New("traffic write failed"), time.Now())
	window.RecordSuccess("node authorization refresh", time.Now())
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("remaining accounting failure did not expire")
	}
	if err := window.Err(time.Now()); err == nil {
		t.Fatal("missing accounting expiration error")
	}
}

func TestFailClosedWindowSuccessCancelsDeadline(t *testing.T) {
	canceled := make(chan struct{}, 1)
	window := newFailClosedWindow(20*time.Millisecond, func() { canceled <- struct{}{} })
	defer window.Close()
	window.RecordFailure("traffic accounting", errors.New("traffic write failed"), time.Now())
	window.RecordSuccess("traffic accounting", time.Now())
	select {
	case <-canceled:
		t.Fatal("successful traffic flush did not recover the fail-closed window")
	case <-time.After(60 * time.Millisecond):
	}
}

func TestFailClosedWindowZeroGraceExpiresImmediately(t *testing.T) {
	canceled := make(chan struct{}, 1)
	window := newFailClosedWindow(0, func() { canceled <- struct{}{} })
	defer window.Close()
	_, remaining, expired := window.RecordFailure("traffic accounting", errors.New("write failed"), time.Now())
	if remaining != 0 || !expired {
		t.Fatalf("zero-grace failure remaining=%v expired=%v", remaining, expired)
	}
	select {
	case <-canceled:
	default:
		t.Fatal("zero-grace failure did not cancel immediately")
	}
}

func TestProtocolSwitchValidation(t *testing.T) {
	t.Setenv("NODE_ID", "1")
	t.Setenv("ENABLE_TCP", "not-a-boolean")
	if err := LoadConfig().Validate(); err == nil {
		t.Fatal("invalid ENABLE_TCP value was accepted")
	}

	t.Setenv("ENABLE_TCP", "false")
	t.Setenv("ENABLE_UDP", "false")
	if err := LoadConfig().Validate(); err == nil {
		t.Fatal("configuration with TCP and UDP both disabled was accepted")
	}
}

func TestDisabledProtocolIgnoresItsTuningParameters(t *testing.T) {
	config := LoadConfig()
	config.NodeID = 1
	config.EnableTCP = true
	config.EnableUDP = false
	config.UDPMTU = 0
	config.UDPRelayBatchSize = 0
	config.UDPServerBatchSize = 0
	config.UDPSendQueueSize = 0
	config.UDPNATTimeoutSeconds = 0
	config.UDPMaxSessions = 0
	config.UDPMaxSessionsPerUser = 0
	if err := config.Validate(); err != nil {
		t.Fatalf("disabled UDP settings were validated: %v", err)
	}

	config.EnableTCP = false
	config.EnableUDP = true
	config.UDPMTU = 1496
	config.UDPRelayBatchSize = 8
	config.UDPServerBatchSize = 64
	config.UDPSendQueueSize = 1024
	config.UDPNATTimeoutSeconds = 60
	config.UDPMaxSessions = 2048
	config.UDPMaxSessionsPerUser = 128
	config.TCPMaxHandshakes = 0
	config.TCPMaxConnectionsPerUser = -1
	config.TCPTrafficFlushSeconds = 0
	if err := config.Validate(); err != nil {
		t.Fatalf("disabled TCP settings were validated: %v", err)
	}
}

func TestTCPConnectionLimitValidation(t *testing.T) {
	config := LoadConfig()
	config.NodeID = 1
	config.TCPMaxConnectionsPerUser = -1
	if err := config.Validate(); err == nil {
		t.Fatal("negative per-user TCP connection limit was accepted")
	}

	config.TCPMaxConnectionsPerUser = 0
	config.TCPMaxEstablishedTotal = -1
	if err := config.Validate(); err == nil {
		t.Fatal("negative total established TCP connection limit was accepted")
	}

	config.TCPMaxEstablishedTotal = 0
	if err := config.Validate(); err != nil {
		t.Fatalf("unlimited per-user TCP connections were rejected: %v", err)
	}
}

func TestRuntimeMetricsSnapshot(t *testing.T) {
	metrics := readRuntimeMetrics()
	if metrics.memoryHeapBytes == 0 || metrics.memorySysBytes == 0 || metrics.goroutines < 1 {
		t.Fatalf("invalid runtime metrics: %+v", metrics)
	}
}

func TestPendingStateMetrics(t *testing.T) {
	state := NewState()
	state.AddTraffic(7, 100, 200)
	state.AddTraffic(9, 30, 40)
	state.AddAliveIP(7, "192.0.2.1")
	state.AddAliveIP(7, "192.0.2.2")
	metrics := state.PendingMetrics()
	if metrics.TrafficUsers != 2 || metrics.TrafficUploadBytes != 130 || metrics.TrafficDownloadBytes != 240 ||
		metrics.AliveUsers != 1 || metrics.AliveRecords != 2 {
		t.Fatalf("unexpected pending state metrics: %+v", metrics)
	}
}

func TestDatabaseHealthTracksRecovery(t *testing.T) {
	health := &databaseHealth{}
	failedAt := time.Now().Add(-time.Millisecond)
	health.Record("reportTraffic", failedAt, errors.New("timeout"))
	health.Record("reportTraffic", failedAt, errors.New("timeout"))
	snapshot := health.Snapshot()
	if snapshot.Failures != 2 || snapshot.ConsecutiveFailures != 2 || snapshot.LastFailure.IsZero() {
		t.Fatalf("unexpected failed health snapshot: %+v", snapshot)
	}
	health.Record("reportTraffic", failedAt, nil)
	snapshot = health.Snapshot()
	if snapshot.Successes != 1 || snapshot.ConsecutiveFailures != 0 || snapshot.LastSuccess.IsZero() {
		t.Fatalf("unexpected recovered health snapshot: %+v", snapshot)
	}
	health.Record("reportTraffic", failedAt, errors.New("timeout"))
	health.Record("reportNodeStatus", failedAt, nil)
	snapshot = health.Snapshot()
	if snapshot.Operations["reportTraffic"].consecutiveFailures != 1 || snapshot.Operations["reportNodeStatus"].consecutiveFailures != 0 {
		t.Fatalf("operation health was not tracked independently: %+v", snapshot.Operations)
	}
}

func TestUDPSessionProtectionValidation(t *testing.T) {
	config := LoadConfig()
	config.NodeID = 1
	config.UDPNATTimeoutSeconds = 59
	if err := config.Validate(); err == nil {
		t.Fatal("UDP NAT timeout below the SS2022 minimum was accepted")
	}

	config.UDPNATTimeoutSeconds = 60
	config.UDPMaxSessions = 128
	config.UDPMaxSessionsPerUser = 129
	if err := config.Validate(); err == nil {
		t.Fatal("per-user UDP session limit above the global limit was accepted")
	}
}
