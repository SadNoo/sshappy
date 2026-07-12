package panel

import (
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
	t.Setenv("TRAFFIC_BATCH_RETENTION_DAYS", "")
	t.Setenv("MYSQL_CONNECT_TIMEOUT_SECONDS", "")
	t.Setenv("MYSQL_IO_TIMEOUT_SECONDS", "")
	config := LoadConfig()
	if !config.EnableTCP || !config.EnableUDP ||
		config.TCPMaxHandshakes != 1024 ||
		config.TCPMaxConnectionsPerUser != 800 ||
		config.TCPTrafficFlushSeconds != 30 ||
		config.TrafficBatchRetentionDays != 30 ||
		config.MySQLConnectTimeoutSeconds != 10 ||
		config.MySQLIOTimeoutSeconds != 30 {
		t.Fatalf("unexpected operational defaults: %+v", config)
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
