//go:build linux

package panel

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/logging"
	"github.com/database64128/shadowsocks-go/netio"
	"github.com/database64128/shadowsocks-go/ss2022"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestUpstreamTCPRelayRoundTripAndAccounting(t *testing.T) {
	port := reserveTCPPort(t)
	serverKey := bytes.Repeat([]byte{0x31}, KeyLen)
	userKey := bytes.Repeat([]byte{0x52}, KeyLen)
	user := User{ID: 9, UserKey: userKey}
	credentialPath := filepath.Join(t.TempDir(), "users.json")
	if err := writeCredentialFile(credentialPath, []User{user}); err != nil {
		t.Fatal(err)
	}
	state := NewState()
	runtime := NewRuntime(state)
	runtime.ReplaceUsers([]User{user})
	logger, err := logging.NewZapLogger("production", zapcore.ErrorLevel)
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Sync()
	config := Config{
		ListenHost:               "127.0.0.1",
		EnableTCP:                true,
		EnableUDP:                false,
		UDPMTU:                   1496,
		UDPRelayBatchSize:        256,
		UDPServerBatchSize:       64,
		UDPSendQueueSize:         1024,
		CredentialPath:           credentialPath,
		SyncIntervalSeconds:      60,
		TCPMaxConnectionsPerUser: 1,
		TCPTrafficFlushSeconds:   1,
	}
	manager, _, err := newManager(config, Node{ID: 1, ListenPort: port, ServerKey: serverKey}, runtime, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan bool, 1)
	go func() {
		done <- manager.Run(ctx)
	}()
	stopped := false
	defer func() {
		if stopped {
			return
		}
		cancel()
		if ok := <-done; !ok {
			t.Error("upstream manager stopped with an error")
		}
	}()
	waitForTCPListener(t, port)

	echoListener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echoListener.Close()
	go func() {
		connection, err := echoListener.AcceptTCP()
		if err != nil {
			return
		}
		defer connection.Close()
		_, _ = io.Copy(connection, connection)
	}()

	clientCipher, err := ss2022.NewClientCipherConfig(userKey, [][]byte{serverKey}, true)
	if err != nil {
		t.Fatal(err)
	}
	innerClient := (&netio.TCPClientConfig{
		Name:    "direct",
		Network: "tcp",
		Dialer:  conn.DefaultTCPDialer,
	}).NewTCPClient()
	client := (&ss2022.StreamClientConfig{
		Name:         "test",
		InnerClient:  innerClient,
		Addr:         conn.AddrFromIPAndPort(netip.MustParseAddr("127.0.0.1"), uint16(port)),
		CipherConfig: clientCipher,
	}).NewStreamClient()
	payload := bytes.Repeat([]byte("upstream-tcp-"), 4096)
	clientConnection, err := client.DialStream(
		context.Background(),
		conn.AddrFromIPPort(echoListener.Addr().(*net.TCPAddr).AddrPort()),
		payload,
	)
	if err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(clientConnection, response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, payload) {
		t.Fatal("TCP response mismatch")
	}
	waitForTrafficTotals(t, state, int64(len(payload)), int64(len(payload)), 3*time.Second)

	rejectedConnection, err := client.DialStream(
		context.Background(),
		conn.AddrFromIPPort(echoListener.Addr().(*net.TCPAddr).AddrPort()),
		[]byte("over-user-limit"),
	)
	if err == nil {
		defer rejectedConnection.Close()
		if err := rejectedConnection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		var b [1]byte
		_, readErr := rejectedConnection.Read(b[:])
		if readErr == nil {
			t.Fatal("second connection for the same user remained open above the limit")
		}
		if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
			t.Fatal("second connection for the same user was not closed by the limit")
		}
	}

	secondPayload := bytes.Repeat([]byte("shutdown-accounting-"), 2048)
	if _, err := clientConnection.Write(secondPayload); err != nil {
		t.Fatal(err)
	}
	secondResponse := make([]byte, len(secondPayload))
	if _, err := io.ReadFull(clientConnection, secondResponse); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secondResponse, secondPayload) {
		t.Fatal("second TCP response mismatch")
	}

	cancel()
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("upstream manager stopped with an error")
		}
		stopped = true
	case <-time.After(3 * time.Second):
		t.Fatal("upstream manager did not stop active TCP connection")
	}
	waitForTrafficTotals(t, state, int64(len(secondPayload)), int64(len(secondPayload)), time.Second)
	_ = clientConnection.Close()
}

func waitForTrafficTotals(t *testing.T, state *State, wantUpload, wantDownload int64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		traffic := state.SnapshotTraffic()
		var upload, download int64
		for _, delta := range traffic {
			upload += delta.Upload
			download += delta.Download
		}
		if upload == wantUpload && download == wantDownload {
			return
		}
		state.MergeTraffic(traffic)
		if time.Now().After(deadline) {
			t.Fatalf("TCP traffic upload=%d download=%d, want %d/%d", upload, download, wantUpload, wantDownload)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestUpstreamUDPRelayRoundTripAndAccounting(t *testing.T) {
	port := reserveTCPPort(t)
	serverKey := make([]byte, KeyLen)
	userKey := make([]byte, KeyLen)
	for i := range serverKey {
		serverKey[i] = byte(i)
		userKey[i] = byte(KeyLen - i)
	}
	user := User{ID: 7, UserKey: userKey}
	credentialPath := filepath.Join(t.TempDir(), "users.json")
	if err := writeCredentialFile(credentialPath, []User{user}); err != nil {
		t.Fatal(err)
	}

	state := NewState()
	runtime := NewRuntime(state)
	runtime.ReplaceUsers([]User{user})
	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)
	defer logger.Sync()
	config := Config{
		ListenHost:          "127.0.0.1",
		EnableTCP:           false,
		EnableUDP:           true,
		UDPMTU:              1496,
		UDPRelayBatchSize:   256,
		UDPServerBatchSize:  64,
		UDPSendQueueSize:    1024,
		CredentialPath:      credentialPath,
		SyncIntervalSeconds: 60,
	}
	node := Node{ID: 1, ListenPort: port, ServerKey: serverKey}
	manager, managedServer, err := newManager(config, node, runtime, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan bool, 1)
	go func() {
		done <- manager.Run(ctx)
	}()
	defer func() {
		cancel()
		if ok := <-done; !ok {
			t.Error("upstream manager stopped with an error")
		}
	}()
	waitForLogMessage(t, logs, "Started UDP session relay service listener")

	echoConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echoConn.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := echoConn.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			_, _ = echoConn.WriteToUDPAddrPort(buf[:n], addr)
		}
	}()

	clientCipher, err := ss2022.NewClientCipherConfig(userKey, [][]byte{serverKey}, true)
	if err != nil {
		t.Fatal(err)
	}
	serverAddr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))
	client := ss2022.NewUDPClient(
		"test",
		"ip",
		conn.AddrFromIPPort(serverAddr),
		1496,
		conn.DefaultUDPClientListenConfig,
		ss2022.DefaultSlidingWindowFilterSize,
		clientCipher,
		ss2022.NoPadding,
	)
	clientInfo, session, err := client.NewSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	const packetCount = 1000
	target := conn.AddrFromIPPort(echoConn.LocalAddr().(*net.UDPAddr).AddrPort())
	received := make(chan uint64, packetCount)
	readError := make(chan error, 1)
	go func() {
		readBuf := make([]byte, 2048)
		for range packetCount {
			_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, source, err := clientConn.ReadFromUDPAddrPort(readBuf)
			if err != nil {
				readError <- err
				return
			}
			_, start, length, err := session.Unpacker.UnpackInPlace(readBuf, source, 0, n)
			if err != nil {
				readError <- err
				return
			}
			received <- binary.BigEndian.Uint64(readBuf[start : start+length])
		}
	}()
	for i := 0; i < packetCount; i++ {
		buf := make([]byte, clientInfo.PackerHeadroom.Front+8+clientInfo.PackerHeadroom.Rear)
		binary.BigEndian.PutUint64(buf[clientInfo.PackerHeadroom.Front:], uint64(i))
		dest, start, length, err := session.Packer.PackInPlace(
			context.Background(),
			buf,
			target,
			clientInfo.PackerHeadroom.Front,
			8,
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := clientConn.WriteToUDPAddrPort(buf[start:start+length], dest); err != nil {
			t.Fatal(err)
		}
		// Keep the load sustained while retaining small bursts for mmsg coverage.
		// An instantaneous localhost burst only measures the host's UDP socket cap.
		if i%4 == 3 {
			time.Sleep(time.Millisecond)
		}
	}

	seen := make(map[uint64]struct{}, packetCount)
	for len(seen) < packetCount {
		select {
		case value := <-received:
			seen[value] = struct{}{}
		case err := <-readError:
			t.Fatalf("received %d/%d: %v", len(seen), packetCount, err)
		case <-time.After(8 * time.Second):
			t.Fatalf("received %d/%d", len(seen), packetCount)
		}
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		traffic := state.SnapshotTraffic()
		var upload, download int64
		for _, delta := range traffic {
			upload += delta.Upload
			download += delta.Download
		}
		if upload == packetCount*8 && download == packetCount*8 {
			break
		}
		state.MergeTraffic(traffic)
		if time.Now().After(deadline) {
			t.Fatalf("traffic upload=%d download=%d", upload, download)
		}
		time.Sleep(10 * time.Millisecond)
	}

	hotUserKey := make([]byte, KeyLen)
	for i := range hotUserKey {
		hotUserKey[i] = byte(2*KeyLen - i)
	}
	hotUser := User{ID: 8, UserKey: hotUserKey}
	if err := managedServer.AddCredential("8", hotUserKey); err != nil {
		t.Fatal(err)
	}
	runtime.ReplaceUsers([]User{user, hotUser})
	hotCipher, err := ss2022.NewClientCipherConfig(hotUserKey, [][]byte{serverKey}, true)
	if err != nil {
		t.Fatal(err)
	}
	hotClient := ss2022.NewUDPClient(
		"hot-update",
		"ip",
		conn.AddrFromIPPort(serverAddr),
		1496,
		conn.DefaultUDPClientListenConfig,
		ss2022.DefaultSlidingWindowFilterSize,
		hotCipher,
		ss2022.NoPadding,
	)
	hotInfo, hotSession, err := hotClient.NewSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer hotSession.Close()
	hotBuf := make([]byte, hotInfo.PackerHeadroom.Front+8+hotInfo.PackerHeadroom.Rear)
	binary.BigEndian.PutUint64(hotBuf[hotInfo.PackerHeadroom.Front:], 999)
	dest, start, length, err := hotSession.Packer.PackInPlace(
		context.Background(),
		hotBuf,
		target,
		hotInfo.PackerHeadroom.Front,
		8,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clientConn.WriteToUDPAddrPort(hotBuf[start:start+length], dest); err != nil {
		t.Fatal(err)
	}
	readBuf := make([]byte, 2048)
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, source, err := clientConn.ReadFromUDPAddrPort(readBuf)
	if err != nil {
		t.Fatal(err)
	}
	_, start, length, err = hotSession.Unpacker.UnpackInPlace(readBuf, source, 0, n)
	if err != nil {
		t.Fatal(err)
	}
	if value := binary.BigEndian.Uint64(readBuf[start : start+length]); value != 999 {
		t.Fatalf("hot update response = %d", value)
	}
}

func reserveTCPPort(t *testing.T) int {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func waitForTCPListener(t *testing.T, port int) {
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	deadline := time.Now().Add(2 * time.Second)
	for {
		connection, err := net.DialTimeout("tcp", address, 50*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("TCP listener did not start: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForLogMessage(t *testing.T, logs *observer.ObservedLogs, message string) {
	deadline := time.Now().Add(2 * time.Second)
	for {
		if logs.FilterMessage(message).Len() > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("log message %q was not observed", message)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
