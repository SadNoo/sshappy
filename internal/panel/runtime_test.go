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
	config := LoadConfig()
	if config.UDPMTU != 1496 ||
		config.UDPRelayBatchSize != 256 ||
		config.UDPServerBatchSize != 64 ||
		config.UDPSendQueueSize != 1024 {
		t.Fatalf("unexpected UDP defaults: %+v", config)
	}
}
