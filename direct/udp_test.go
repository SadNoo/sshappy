package direct

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/socks5"
	"go.uber.org/zap"
)

const socks5CancellationTestTimeout = 5 * time.Second

func TestSocks5UDPNewSessionCancellationInterruptsHandshake(t *testing.T) {
	for _, test := range []struct {
		name    string
		authMsg []byte
	}{
		{name: "plain"},
		{name: "username-password", authMsg: (socks5.UserInfo{Username: "user", Password: "password"}).AppendAuthMsg(nil)},
	} {
		t.Run(test.name, func(t *testing.T) {
			listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()

			accepted := make(chan *net.TCPConn, 1)
			acceptErr := make(chan error, 1)
			go func() {
				serverConn, err := listener.AcceptTCP()
				if err != nil {
					acceptErr <- err
					return
				}
				accepted <- serverConn
			}()

			client := (&Socks5UDPClientConfig{
				Logger:     zap.NewNop(),
				Name:       "test",
				NetworkTCP: "tcp4",
				NetworkIP:  "ip4",
				Address:    listener.Addr().String(),
				Dialer:     (conn.DialerSocketOptions{}).Dialer(),
				MTU:        1500,
				AuthMsg:    test.authMsg,
			}).NewClient()

			ctx, cancel := context.WithCancel(t.Context())
			result := make(chan error, 1)
			go func() {
				_, _, err := client.NewSession(ctx)
				result <- err
			}()

			var serverConn *net.TCPConn
			select {
			case serverConn = <-accepted:
				defer serverConn.Close()
			case err := <-acceptErr:
				t.Fatal(err)
			case <-time.After(socks5CancellationTestTimeout):
				t.Fatal("SOCKS5 client did not connect")
			}

			// The fake server deliberately never answers the method negotiation.
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("NewSession error = %v, want context cancellation", err)
				}
			case <-time.After(socks5CancellationTestTimeout):
				t.Fatal("NewSession remained blocked after context cancellation")
			}
		})
	}
}

func TestSocks5UDPAssociateContextCancellationWinsSuccessRace(t *testing.T) {
	clientConn, serverConn := newLocalTCPPair(t)
	defer serverConn.Close()

	ctx, cancel := context.WithCancel(t.Context())
	_, err := socks5UDPAssociateContext(ctx, clientConn, func() (conn.Addr, error) {
		cancel()
		return conn.AddrFromIPPort(serverConn.LocalAddr().(*net.TCPAddr).AddrPort()), nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("associate error = %v, want context cancellation", err)
	}
	if err := clientConn.Close(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("client connection remained open after cancellation race: %v", err)
	}
}

func TestSocks5UDPAssociateContextSuccessStopsCancellationCallback(t *testing.T) {
	clientConn, serverConn := newLocalTCPPair(t)
	defer clientConn.Close()
	defer serverConn.Close()

	ctx, cancel := context.WithCancel(t.Context())
	_, err := socks5UDPAssociateContext(ctx, clientConn, func() (conn.Addr, error) {
		return conn.AddrFromIPPort(serverConn.LocalAddr().(*net.TCPAddr).AddrPort()), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	cancel()

	if _, err := clientConn.Write([]byte{1}); err != nil {
		t.Fatalf("late context cancellation closed a successful association: %v", err)
	}
	if err := serverConn.SetReadDeadline(time.Now().Add(socks5CancellationTestTimeout)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := serverConn.Read(buf); err != nil {
		t.Fatalf("failed to read from successful association: %v", err)
	}
}

func newLocalTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan *net.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		serverConn, err := listener.AcceptTCP()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- serverConn
	}()

	dialer := (conn.DialerSocketOptions{}).Dialer()
	clientConn, _, err := dialer.DialTCP(t.Context(), "tcp4", listener.Addr().String(), nil)
	if err != nil {
		t.Fatal(err)
	}

	select {
	case serverConn := <-accepted:
		return clientConn, serverConn
	case err := <-acceptErr:
		_ = clientConn.Close()
		t.Fatal(err)
	case <-time.After(socks5CancellationTestTimeout):
		_ = clientConn.Close()
		t.Fatal("timed out accepting local TCP connection")
	}
	return nil, nil
}
