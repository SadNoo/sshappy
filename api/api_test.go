package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/database64128/shadowsocks-go/conn"
	"go.uber.org/zap"
)

func TestBearerAuthMiddleware(t *testing.T) {
	handler := newBearerAuthMiddleware("test-token")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	tests := []struct {
		name   string
		header string
		status int
	}{
		{name: "missing", status: http.StatusUnauthorized},
		{name: "wrong scheme", header: "Basic test-token", status: http.StatusUnauthorized},
		{name: "wrong token", header: "Bearer wrong-token", status: http.StatusUnauthorized},
		{name: "valid", header: "Bearer test-token", status: http.StatusNoContent},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if test.header != "" {
				req.Header.Set("Authorization", test.header)
			}
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != test.status {
				t.Fatalf("status = %d, want %d", rr.Code, test.status)
			}
		})
	}
}

func TestRealIPMiddlewareMalformedRemoteAddrStillServesRequest(t *testing.T) {
	called := false
	handler := newRealIPMiddleware(
		zap.NewNop(),
		[]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		"X-Real-IP",
	)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "malformed-remote-address"
	req.Header.Set("X-Real-IP", "192.0.2.1")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Fatal("next handler was not called")
	}
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusNoContent)
	}
}

func TestServerStartRollsBackEarlierListener(t *testing.T) {
	blocker, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()

	lc := conn.NewListenConfigCache().Get(conn.ListenerSocketOptions{})
	server := &Server{
		logger: zap.NewNop(),
		lcs: []listenConfig{
			{listenConfig: lc, network: "tcp4", address: "127.0.0.1:0"},
			{listenConfig: lc, network: "tcp4", address: blocker.Addr().String()},
		},
		server: http.Server{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})},
	}

	if err := server.Start(context.Background()); err == nil {
		t.Fatal("Start succeeded despite occupied second address")
	}
	if len(server.listeners) != 1 {
		t.Fatalf("opened listener count = %d, want 1", len(server.listeners))
	}
	if err := server.listeners[0].Close(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("first listener remained open after rollback: Close error = %v", err)
	}
}

func TestJoinPatternPath(t *testing.T) {
	for _, c := range []struct {
		elem []string
		want string
	}{
		{[]string{}, ""},
		{[]string{""}, ""},
		{[]string{"a"}, "a"},
		{[]string{"/"}, "/"},
		{[]string{"/a"}, "/a"},
		{[]string{"a/"}, "a/"},
		{[]string{"/a/"}, "/a/"},
		{[]string{"", "b"}, "b"},
		{[]string{"", "/b"}, "/b"},
		{[]string{"", "b/"}, "b/"},
		{[]string{"", "/b/"}, "/b/"},
		{[]string{"a", "b"}, "a/b"},
		{[]string{"a", "/b"}, "a/b"},
		{[]string{"a", "b/"}, "a/b/"},
		{[]string{"a", "/b/"}, "a/b/"},
		{[]string{"/", "b"}, "/b"},
		{[]string{"/", "/b"}, "/b"},
		{[]string{"/", "b/"}, "/b/"},
		{[]string{"/", "/b/"}, "/b/"},
		{[]string{"/a", "b"}, "/a/b"},
		{[]string{"/a", "/b"}, "/a/b"},
		{[]string{"/a", "b/"}, "/a/b/"},
		{[]string{"/a", "/b/"}, "/a/b/"},
		{[]string{"a/", "b"}, "a/b"},
		{[]string{"a/", "/b"}, "a/b"},
		{[]string{"a/", "b/"}, "a/b/"},
		{[]string{"a/", "/b/"}, "a/b/"},
		{[]string{"/a/", "b"}, "/a/b"},
		{[]string{"/a/", "/b"}, "/a/b"},
		{[]string{"/a/", "b/"}, "/a/b/"},
		{[]string{"/a/", "/b/"}, "/a/b/"},
	} {
		if got := joinPatternPath(c.elem...); got != c.want {
			t.Errorf("joinPatternPath(%#v) = %q; want %q", c.elem, got, c.want)
		}
	}
}
