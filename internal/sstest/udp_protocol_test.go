package sstest

import (
	"bytes"
	"context"
	"net/netip"
	"testing"

	ssconn "github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/ss2022"
)

func TestUpstreamUDPRejectsReplayAndRoundTrips(t *testing.T) {
	serverKey := make([]byte, 32)
	userKey := make([]byte, 32)
	for i := range serverKey {
		serverKey[i] = byte(i)
		userKey[i] = byte(31 - i)
	}
	identityConfig, err := ss2022.NewServerIdentityCipherConfig(serverKey, true)
	if err != nil {
		t.Fatal(err)
	}
	server := ss2022.NewUDPServer(
		ss2022.DefaultSlidingWindowFilterSize,
		ss2022.UserCipherConfig{},
		identityConfig,
		ss2022.NoPadding,
	)
	serverUser, err := ss2022.NewServerUserCipherConfig("7", userKey, true)
	if err != nil {
		t.Fatal(err)
	}
	server.ReplaceUserLookupMap(ss2022.UserLookupMap{
		ss2022.PSKHash(userKey): serverUser,
	})
	clientConfig, err := ss2022.NewClientCipherConfig(userKey, [][]byte{serverKey}, true)
	if err != nil {
		t.Fatal(err)
	}
	serverAddr := netip.MustParseAddrPort("127.0.0.1:23336")
	client := ss2022.NewUDPClient(
		"test",
		"ip",
		ssconn.AddrFromIPPort(serverAddr),
		1500,
		ssconn.DefaultUDPClientListenConfig,
		ss2022.DefaultSlidingWindowFilterSize,
		clientConfig,
		ss2022.NoPadding,
	)
	_, clientSession, err := client.NewSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, udpPacketCapacity)
	payload := []byte("upstream-udp")
	copy(buf[udpPacketHeadroom:], payload)
	targetAddr := netip.MustParseAddrPort("127.0.0.1:5353")
	_, packetStart, packetLen, err := clientSession.Packer.PackInPlace(
		context.Background(),
		buf,
		ssconn.AddrFromIPPort(targetAddr),
		udpPacketHeadroom,
		len(payload),
	)
	if err != nil {
		t.Fatal(err)
	}
	replay := append([]byte(nil), buf[packetStart:packetStart+packetLen]...)
	packet := buf[packetStart : packetStart+packetLen]
	clientSessionID, err := server.SessionInfo(packet)
	if err != nil {
		t.Fatal(err)
	}
	unpacker, username, err := server.NewUnpacker(packet, clientSessionID)
	if err != nil {
		t.Fatal(err)
	}
	if username != "7" {
		t.Fatalf("username = %q", username)
	}
	target, payloadStart, payloadLen, err := unpacker.UnpackInPlace(
		buf,
		netip.MustParseAddrPort("127.0.0.1:40000"),
		packetStart,
		packetLen,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !target.Equals(ssconn.AddrFromIPPort(targetAddr)) {
		t.Fatalf("target = %s", target)
	}
	if !bytes.Equal(buf[payloadStart:payloadStart+payloadLen], payload) {
		t.Fatalf("payload = %x", buf[payloadStart:payloadStart+payloadLen])
	}

	replayBuf := make([]byte, udpPacketHeadroom+len(replay)+32)
	copy(replayBuf[udpPacketHeadroom:], replay)
	replayPacket := replayBuf[udpPacketHeadroom : udpPacketHeadroom+len(replay)]
	if _, err := server.SessionInfo(replayPacket); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := unpacker.UnpackInPlace(
		replayBuf,
		netip.MustParseAddrPort("127.0.0.1:40000"),
		udpPacketHeadroom,
		len(replay),
	); err == nil {
		t.Fatal("replayed packet was accepted")
	}

	packer, err := unpacker.NewPacker()
	if err != nil {
		t.Fatal(err)
	}
	packetStart, packetLen, err = packer.PackInPlace(
		buf,
		targetAddr,
		payloadStart,
		payloadLen,
		1472,
	)
	if err != nil {
		t.Fatal(err)
	}
	source, payloadStart, payloadLen, err := clientSession.Unpacker.UnpackInPlace(
		buf,
		serverAddr,
		packetStart,
		packetLen,
	)
	if err != nil {
		t.Fatal(err)
	}
	if source != targetAddr || !bytes.Equal(buf[payloadStart:payloadStart+payloadLen], payload) {
		t.Fatalf("response source=%s payload=%x", source, buf[payloadStart:payloadStart+payloadLen])
	}
}
