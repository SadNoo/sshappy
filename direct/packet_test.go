package direct

import (
	"net/netip"
	"testing"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

const (
	mtu        = 1500
	packetSize = 1452
)

var (
	targetAddr     = conn.AddrFromIPPort(targetAddrPort)
	targetAddrPort = netip.AddrPortFrom(netip.IPv6Unspecified(), 53)
	serverAddrPort = netip.AddrPortFrom(netip.IPv6Unspecified(), 1080)
)

func TestDirectPacketPackUnpacker(t *testing.T) {
	c := NewDirectPacketClientPacker("ip", mtu)
	s := NewDirectPacketServerPackUnpacker(targetAddr, false) // Cheat a little bit, because we have to. :P
	zerocopy.ClientServerPackerUnpackerTestFunc(t, c, DirectPacketClientUnpacker{}, s, s)
}

func TestDirectUDPClientUsesPerSessionPacker(t *testing.T) {
	c := NewDirectUDPClient("direct", "ip", mtu, conn.DefaultUDPClientListenConfig)
	_, first, err := c.NewSession(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := c.NewSession(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	firstPacker, ok := first.Packer.(*DirectPacketClientPacker)
	if !ok {
		t.Fatalf("first packer has type %T", first.Packer)
	}
	secondPacker, ok := second.Packer.(*DirectPacketClientPacker)
	if !ok {
		t.Fatalf("second packer has type %T", second.Packer)
	}
	if firstPacker == secondPacker {
		t.Fatal("DirectUDPClient reused a mutable packer across sessions")
	}
}

func TestShadowsocksNonePacketPackUnpacker(t *testing.T) {
	clientPacker := NewShadowsocksNonePacketClientPacker(serverAddrPort, packetSize)
	clientUnpacker := NewShadowsocksNonePacketClientUnpacker(serverAddrPort)
	zerocopy.ClientServerPackerUnpackerTestFunc(t, clientPacker, clientUnpacker, ShadowsocksNonePacketServerPacker{}, &ShadowsocksNonePacketServerUnpacker{})
}

func TestSocks5PacketPackUnpacker(t *testing.T) {
	clientPacker := NewSocks5PacketClientPacker(serverAddrPort, packetSize)
	clientUnpacker := NewSocks5PacketClientUnpacker(serverAddrPort)
	zerocopy.ClientServerPackerUnpackerTestFunc(t, clientPacker, clientUnpacker, Socks5PacketServerPacker{}, &Socks5PacketServerUnpacker{})
}
