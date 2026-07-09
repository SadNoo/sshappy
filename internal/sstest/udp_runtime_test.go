package sstest

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	ssconn "github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/ss2022"
)

func TestUDPRuntimeBurstRoundTrip(t *testing.T) {
	echoConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echoConn.Close()
	_ = echoConn.SetReadBuffer(4 << 20)
	_ = echoConn.SetWriteBuffer(4 << 20)
	go udpEchoLoop(echoConn)

	serverKey := make([]byte, 32)
	userKey := make([]byte, 32)
	for i := range serverKey {
		serverKey[i] = byte(i)
		userKey[i] = byte(31 - i)
	}
	user := User{
		ID:           7,
		UserKey:      userKey,
		IdentityHash: identityHash(userKey),
	}
	config := Config{
		UDPIdleTimeout:      60,
		UDPMTU:              1500,
		UDPReadBufferBytes:  4 << 20,
		UDPWriteBufferBytes: 4 << 20,
		UDPQueueSize:        4096,
		TCPConnectTimeout:   2,
	}
	runtime := newUDPRuntime(config, NewRuntimeState())
	if err := runtime.configure(NodeInfo{ServerKey: serverKey}, []User{user}); err != nil {
		t.Fatal(err)
	}
	inbound, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer inbound.Close()
	tuneUDP(inbound, config)
	go runtime.serve(inbound)
	defer runtime.closeAll()

	serverAddr := inbound.LocalAddr().(*net.UDPAddr).AddrPort()
	clientConfig, err := ss2022.NewClientCipherConfig(userKey, [][]byte{serverKey}, true)
	if err != nil {
		t.Fatal(err)
	}
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
	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	_ = clientConn.SetReadBuffer(4 << 20)
	_ = clientConn.SetWriteBuffer(4 << 20)

	const packetCount = 400
	received := make(chan uint64, packetCount)
	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 65535)
		for i := 0; i < packetCount; i++ {
			_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, packetSource, err := clientConn.ReadFromUDPAddrPort(buf)
			if err != nil {
				readErr <- err
				return
			}
			source, payloadStart, payloadLen, err := clientSession.Unpacker.UnpackInPlace(
				buf,
				packetSource,
				0,
				n,
			)
			if err != nil {
				readErr <- err
				return
			}
			if source != echoConn.LocalAddr().(*net.UDPAddr).AddrPort() || payloadLen != 8 {
				readErr <- errors.New("unexpected response source or payload length")
				return
			}
			received <- binary.BigEndian.Uint64(buf[payloadStart : payloadStart+payloadLen])
		}
	}()

	target := ssconn.AddrFromIPPort(echoConn.LocalAddr().(*net.UDPAddr).AddrPort())
	for i := uint64(0); i < packetCount; i++ {
		buf := make([]byte, udpPacketCapacity)
		binary.BigEndian.PutUint64(buf[udpPacketHeadroom:], i)
		dest, packetStart, packetLen, err := clientSession.Packer.PackInPlace(
			context.Background(),
			buf,
			target,
			udpPacketHeadroom,
			8,
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := clientConn.WriteToUDPAddrPort(buf[packetStart:packetStart+packetLen], dest); err != nil {
			t.Fatal(err)
		}
	}

	seen := make(map[uint64]struct{}, packetCount)
	for len(seen) < packetCount {
		select {
		case err := <-readErr:
			t.Fatalf(
				"%v: received=%d rx=%d tx=%d decrypt=%d queue=%d target_write=%d pack=%d client_write=%d kernel_in=%d kernel_out=%d",
				err,
				len(seen),
				runtime.metrics.rxPackets.Load(),
				runtime.metrics.txPackets.Load(),
				runtime.metrics.dropDecrypt.Load(),
				runtime.metrics.dropQueueFull.Load(),
				runtime.metrics.dropTargetWrite.Load(),
				runtime.metrics.dropPack.Load(),
				runtime.metrics.dropClientWrite.Load(),
				runtime.metrics.kernelDropIn.Load(),
				runtime.metrics.kernelDropOut.Load(),
			)
		case value := <-received:
			seen[value] = struct{}{}
		case <-time.After(8 * time.Second):
			t.Fatalf("received %d/%d packets", len(seen), packetCount)
		}
	}
	if drops := runtime.metrics.dropQueueFull.Load() +
		runtime.metrics.dropDecrypt.Load() +
		runtime.metrics.dropTargetWrite.Load() +
		runtime.metrics.dropPack.Load() +
		runtime.metrics.dropClientWrite.Load(); drops != 0 {
		t.Fatalf("runtime drops = %d", drops)
	}
	if maxBatch := runtime.metrics.serverRecvMax.Load(); maxBatch <= 1 {
		t.Fatalf("server receive batching was not exercised: max_batch=%d", maxBatch)
	}
	if calls := runtime.metrics.serverRecvCalls.Load(); calls >= packetCount {
		t.Fatalf("server receive syscall count = %d, packets = %d", calls, packetCount)
	}
}

func udpEchoLoop(conn *net.UDPConn) {
	buf := make([]byte, 65535)
	for {
		n, addr, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		_, _ = conn.WriteToUDPAddrPort(buf[:n], addr)
	}
}
