package panel

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"strings"
	"testing"

	"github.com/database64128/shadowsocks-go/conn"
)

func TestRuntimeCompilesSupportedPolicySyntax(t *testing.T) {
	runtime := NewRuntime(NewState())
	rejected := runtime.ReplaceUsers([]User{{
		ID:            7,
		ForbiddenIP:   "192.0.2.4, 2001:db8::/32\n::ffff:198.51.100.0/120",
		ForbiddenPort: "25,1000-1002 2000:2000\t65535",
		DisconnectIP:  "::ffff:203.0.113.5",
	}})
	if len(rejected) != 0 {
		t.Fatalf("valid policy was rejected: %v", rejected)
	}

	allowedSource := netip.MustParseAddrPort("203.0.113.6:12345")
	tests := []struct {
		name   string
		source netip.AddrPort
		target conn.Addr
	}{
		{
			name:   "literal IPv4",
			source: allowedSource,
			target: conn.AddrFromIPAndPort(netip.MustParseAddr("192.0.2.4"), 80),
		},
		{
			name:   "IPv6 prefix",
			source: allowedSource,
			target: conn.AddrFromIPAndPort(netip.MustParseAddr("2001:db8::1"), 80),
		},
		{
			name:   "IPv4-mapped prefix",
			source: allowedSource,
			target: conn.AddrFromIPAndPort(netip.MustParseAddr("198.51.100.8"), 80),
		},
		{
			name:   "single port",
			source: allowedSource,
			target: conn.AddrFromIPAndPort(netip.MustParseAddr("203.0.113.8"), 25),
		},
		{
			name:   "dash range",
			source: allowedSource,
			target: conn.AddrFromIPAndPort(netip.MustParseAddr("203.0.113.8"), 1001),
		},
		{
			name:   "equal colon range",
			source: allowedSource,
			target: conn.AddrFromIPAndPort(netip.MustParseAddr("203.0.113.8"), 2000),
		},
		{
			name:   "maximum port",
			source: allowedSource,
			target: conn.AddrFromIPAndPort(netip.MustParseAddr("203.0.113.8"), 65535),
		},
		{
			name:   "mapped disconnect source",
			source: netip.MustParseAddrPort("203.0.113.5:12345"),
			target: conn.AddrFromIPAndPort(netip.MustParseAddr("203.0.113.8"), 80),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if runtime.Accept("tcp", "7", test.source, test.target) {
				t.Fatal("forbidden request was accepted")
			}
		})
	}

	if !runtime.Accept("tcp", "7", allowedSource, conn.AddrFromIPAndPort(netip.MustParseAddr("203.0.113.8"), 80)) {
		t.Fatal("unrestricted request was rejected")
	}
	if !runtime.Accept("tcp", "7", allowedSource, conn.MustAddrFromDomainPort("allowed.example", 80)) {
		t.Fatal("domain was rejected before final resolution")
	}
}

func TestRuntimeRejectsOnlyUserWithInvalidPolicy(t *testing.T) {
	runtime := NewRuntime(NewState())
	rejected := runtime.ReplaceUsers([]User{
		{ID: 7, ForbiddenIP: "192.0.2.0/24"},
		{ID: 8, Email: "secret@example.invalid", Passwd: "not-for-logs", ForbiddenPort: "25-junk"},
	})
	if len(rejected) != 1 {
		t.Fatalf("rejected policies = %v, want one", rejected)
	}
	if rejected[0].UserID != 8 || rejected[0].Field != "forbidden_port" || rejected[0].RuleIndex != 1 {
		t.Fatalf("unexpected rejection detail: %+v", rejected[0])
	}
	if message := rejected[0].Error(); strings.Contains(message, "secret@example.invalid") || strings.Contains(message, "not-for-logs") {
		t.Fatalf("policy error exposed user credentials: %q", message)
	}

	source := netip.MustParseAddrPort("203.0.113.1:12345")
	target := conn.AddrFromIPAndPort(netip.MustParseAddr("203.0.113.2"), 80)
	if !runtime.Accept("tcp", "7", source, target) {
		t.Fatal("valid peer user was rejected")
	}
	if runtime.Accept("tcp", "8", source, target) {
		t.Fatal("user with malformed policy was accepted")
	}
}

func TestInvalidPolicySyntaxFailsClosed(t *testing.T) {
	tests := []struct {
		name  string
		user  User
		field string
	}{
		{name: "domain as forbidden IP", user: User{ID: 7, ForbiddenIP: "internal.example"}, field: "forbidden_ip"},
		{name: "bad CIDR", user: User{ID: 7, ForbiddenIP: "192.0.2.1/99"}, field: "forbidden_ip"},
		{name: "zero port", user: User{ID: 7, ForbiddenPort: "0"}, field: "forbidden_port"},
		{name: "oversized port", user: User{ID: 7, ForbiddenPort: "65536"}, field: "forbidden_port"},
		{name: "reversed range", user: User{ID: 7, ForbiddenPort: "100-99"}, field: "forbidden_port"},
		{name: "multiple separators", user: User{ID: 7, ForbiddenPort: "1-2-3"}, field: "forbidden_port"},
		{name: "trailing port data", user: User{ID: 7, ForbiddenPort: "25junk"}, field: "forbidden_port"},
		{name: "disconnect CIDR", user: User{ID: 7, DisconnectIP: "203.0.113.0/24"}, field: "disconnect_ip"},
		{name: "nonpositive user ID", user: User{ID: 0}, field: "id"},
		{name: "negative speed limit", user: User{ID: 7, NodeSpeedLimit: -1}, field: "node_speedlimit"},
		{name: "NaN speed limit", user: User{ID: 7, NodeSpeedLimit: math.NaN()}, field: "node_speedlimit"},
		{name: "infinite speed limit", user: User{ID: 7, NodeSpeedLimit: math.Inf(1)}, field: "node_speedlimit"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime := NewRuntime(NewState())
			rejected := runtime.ReplaceUsers([]User{test.user})
			if len(rejected) != 1 || rejected[0].Field != test.field {
				t.Fatalf("rejected = %+v, want field %q", rejected, test.field)
			}
			if runtime.Accept(
				"tcp",
				"7",
				netip.MustParseAddrPort("203.0.113.1:12345"),
				conn.AddrFromIPAndPort(netip.MustParseAddr("203.0.113.2"), 80),
			) {
				t.Fatal("invalid policy user remained authorized")
			}
		})
	}
}

func TestRuntimeResolveAndAcceptTargetUsesExactResolvedIP(t *testing.T) {
	runtime := NewRuntime(NewState())
	if rejected := runtime.ReplaceUsers([]User{{ID: 7, ForbiddenIP: "192.0.2.0/24"}}); len(rejected) != 0 {
		t.Fatal(rejected)
	}
	source := netip.MustParseAddrPort("203.0.113.1:12345")
	runtime.resolveIPPort = func(_ context.Context, target conn.Addr) (netip.AddrPort, error) {
		switch target.Domain() {
		case "allowed.example":
			return netip.MustParseAddrPort("203.0.113.9:80"), nil
		case "blocked.example":
			return netip.MustParseAddrPort("192.0.2.9:80"), nil
		default:
			return netip.AddrPort{}, errors.New("resolver unavailable")
		}
	}

	resolved, accepted, err := runtime.ResolveAndAcceptTarget(t.Context(), "tcp", "7", source, conn.MustAddrFromDomainPort("allowed.example", 80))
	if err != nil || !accepted || !resolved.IsIP() || resolved.IPPort() != netip.MustParseAddrPort("203.0.113.9:80") {
		t.Fatalf("allowed resolution = (%v, %v, %v)", resolved, accepted, err)
	}

	resolved, accepted, err = runtime.ResolveAndAcceptTarget(t.Context(), "tcp", "7", source, conn.MustAddrFromDomainPort("blocked.example", 80))
	if err != nil || accepted || !resolved.IsIP() || resolved.IPPort() != netip.MustParseAddrPort("192.0.2.9:80") {
		t.Fatalf("blocked resolution = (%v, %v, %v)", resolved, accepted, err)
	}

	_, accepted, err = runtime.ResolveAndAcceptTarget(t.Context(), "tcp", "7", source, conn.MustAddrFromDomainPort("missing.example", 80))
	if err == nil || accepted {
		t.Fatalf("DNS failure = (accepted=%v, err=%v), want fail closed", accepted, err)
	}
}

func TestRuntimeResolveRechecksConcurrentPolicyUpdate(t *testing.T) {
	runtime := NewRuntime(NewState())
	runtime.ReplaceUsers([]User{{ID: 7}})
	runtime.resolveIPPort = func(_ context.Context, _ conn.Addr) (netip.AddrPort, error) {
		runtime.ReplaceUsers(nil)
		return netip.MustParseAddrPort("203.0.113.9:80"), nil
	}

	resolved, accepted, err := runtime.ResolveAndAcceptTarget(
		t.Context(),
		"tcp",
		"7",
		netip.MustParseAddrPort("203.0.113.1:12345"),
		conn.MustAddrFromDomainPort("changed.example", 80),
	)
	if err != nil || accepted || !resolved.IsIP() {
		t.Fatalf("concurrent removal resolution = (%v, %v, %v)", resolved, accepted, err)
	}
}
