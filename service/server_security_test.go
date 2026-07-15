package service

import (
	"strings"
	"testing"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/stats"
)

func TestTCPListenerHandshakeCapacityDefaultsAndValidation(t *testing.T) {
	config := TCPListenerConfig{ListenerConfig: ListenerConfig{Network: "tcp", Address: "127.0.0.1:0"}}
	configured, err := config.Configure(conn.NewListenConfigCache(), false, false)
	if err != nil {
		t.Fatal(err)
	}
	if cap(configured.handshakeSlots) != defaultMaxConcurrentHandshakes {
		t.Fatalf("handshake capacity = %d", cap(configured.handshakeSlots))
	}
	if configured.trafficFlushInterval != defaultTCPTrafficFlushInterval {
		t.Fatalf("traffic flush interval = %s", configured.trafficFlushInterval)
	}

	config.MaxConcurrentHandshakes = -1
	if _, err := config.Configure(conn.NewListenConfigCache(), false, false); err == nil {
		t.Fatal("negative handshake capacity was accepted")
	}

	config.MaxConcurrentHandshakes = 0
	config.MaxConnectionsPerUser = -1
	if _, err := config.Configure(conn.NewListenConfigCache(), false, false); err == nil {
		t.Fatal("negative per-user connection capacity was accepted")
	}

	config.MaxConnectionsPerUser = 0
	config.MaxEstablishedConnections = -1
	if _, err := config.Configure(conn.NewListenConfigCache(), false, false); err == nil {
		t.Fatal("negative total established connection capacity was accepted")
	}
}

func TestSocks5UDPWithUserPassAuthIsRejected(t *testing.T) {
	config := ServerConfig{
		Protocol:  "socks5",
		EnableUDP: true,
		Socks5: Socks5ServerConfig{
			EnableUserPassAuth: true,
		},
	}

	err := config.Initialize(nil, nil, stats.Config{}, nil, nil, 0)
	if err == nil || !strings.Contains(err.Error(), "SOCKS5 UDP") {
		t.Fatalf("Initialize error = %v, want SOCKS5 UDP authentication error", err)
	}
}
