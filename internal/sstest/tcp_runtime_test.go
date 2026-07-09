package sstest

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	ssconn "github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/ss2022"
)

func TestTCPRuntimeRoundTripAndAccounting(t *testing.T) {
	echoListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoListener.Close()
	payload := []byte("upstream-tcp-initial-payload")
	go func() {
		conn, err := echoListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, buf); err == nil {
			_, _ = conn.Write(buf)
		}
	}()

	serverKey := make([]byte, 32)
	userKey := make([]byte, 32)
	for i := range serverKey {
		serverKey[i] = byte(i)
		userKey[i] = byte(31 - i)
	}
	user := User{ID: 7, UserKey: userKey, IdentityHash: identityHash(userKey)}
	state := NewRuntimeState()
	server := NewServer(Config{
		ListenHost:          "127.0.0.1",
		TCPConnectTimeout:   2,
		TrafficFlushBytes:   1,
		UDPIdleTimeout:      60,
		UDPMTU:              1500,
		UDPReadBufferBytes:  4 << 20,
		UDPWriteBufferBytes: 4 << 20,
	}, state)
	if err := server.Apply(NodeInfo{ListenPort: 0, ServerKey: serverKey}, []User{user}); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = server.listener.Close()
		_ = server.udpConn.Close()
		server.udp.closeAll()
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = server.Serve(ctx)
	}()

	clientConfig, err := ss2022.NewClientCipherConfig(userKey, [][]byte{serverKey}, false)
	if err != nil {
		t.Fatal(err)
	}
	client := ss2022.NewTCPClient(
		"test",
		"tcp",
		server.listener.Addr().String(),
		ssconn.DefaultTCPDialer,
		true,
		clientConfig,
		nil,
		nil,
	)
	target := echoListener.Addr().(*net.TCPAddr).AddrPort()
	raw, rw, err := client.Dial(
		context.Background(),
		ssconn.AddrFromIPPort(target),
		payload,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	readerInfo := rw.ReaderInfo()
	buf := make([]byte, readerInfo.Headroom.Front+readerInfo.MinPayloadBufferSizePerRead+readerInfo.Headroom.Rear)
	n, err := rw.ReadZeroCopy(buf, readerInfo.Headroom.Front, readerInfo.MinPayloadBufferSizePerRead)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[readerInfo.Headroom.Front:readerInfo.Headroom.Front+n], payload) {
		t.Fatalf("response = %q", buf[readerInfo.Headroom.Front:readerInfo.Headroom.Front+n])
	}
	_ = raw.Close()

	deadline := time.Now().Add(2 * time.Second)
	var upload, download int64
	for {
		for _, delta := range state.SnapshotTraffic() {
			upload += delta.Upload
			download += delta.Download
		}
		if upload == int64(len(payload)) && download == int64(len(payload)) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("traffic was not accounted: upload=%d download=%d", upload, download)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
