package flyskynode

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/router"
)

type staticIPResolver struct {
	answers map[string][][]netip.Addr
	calls   map[string]int
}

func (r *staticIPResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	if network != "ip4" {
		return nil, errors.New("unexpected resolver network")
	}
	if r.calls == nil {
		r.calls = make(map[string]int)
	}
	index := r.calls[host]
	r.calls[host]++
	sets, ok := r.answers[host]
	if !ok || len(sets) == 0 {
		return nil, errors.New("no test answer")
	}
	if index >= len(sets) {
		index = len(sets) - 1
	}
	return sets[index], nil
}

func emptyInterfaceAddrs() ([]net.Addr, error) { return nil, nil }

func newTestOutboundACL(t *testing.T, resolver ipResolver, protected ...netip.Prefix) *outboundACL {
	t.Helper()
	acl, err := newOutboundACLWithDependencies(
		"https://panel.example/api/v1",
		protected,
		resolver,
		emptyInterfaceAddrs,
	)
	if err != nil {
		t.Fatalf("newOutboundACLWithDependencies: %v", err)
	}
	return acl
}

func TestOutboundACLIPv4DefaultPolicy(t *testing.T) {
	acl := newTestOutboundACL(t, &staticIPResolver{})
	tests := []struct {
		name  string
		ip    string
		allow bool
	}{
		{name: "public DNS one", ip: "1.1.1.1", allow: true},
		{name: "public DNS two", ip: "8.8.8.8", allow: true},
		{name: "unspecified", ip: "0.0.0.0"},
		{name: "loopback", ip: "127.0.0.1"},
		{name: "private ten", ip: "10.0.0.1"},
		{name: "private one seven two", ip: "172.16.0.1"},
		{name: "private one nine two", ip: "192.168.1.1"},
		{name: "carrier NAT", ip: "100.64.0.1"},
		{name: "link local metadata", ip: "169.254.169.254"},
		{name: "carrier NAT metadata", ip: "100.100.100.200"},
		{name: "benchmark", ip: "198.18.0.1"},
		{name: "documentation one", ip: "192.0.2.1"},
		{name: "documentation two", ip: "198.51.100.1"},
		{name: "documentation three", ip: "203.0.113.1"},
		{name: "multicast", ip: "239.1.2.3"},
		{name: "reserved", ip: "240.0.0.1"},
		{name: "public IPv6 first release", ip: "2001:4860:4860::8888"},
		{name: "mapped public IPv4", ip: "::ffff:8.8.8.8"},
		{name: "mapped private IPv4", ip: "::ffff:10.0.0.1"},
		{name: "NAT64 public IPv4", ip: "64:ff9b::808:808"},
		{name: "NAT64 metadata IPv4", ip: "64:ff9b::a9fe:a9fe"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			target := conn.AddrFromIPAndPort(netip.MustParseAddr(tc.ip), 443)
			resolved, err := acl.ResolveAndAuthorize(t.Context(), target)
			if tc.allow {
				if err != nil {
					t.Fatalf("allowed target rejected: %v", err)
				}
				if !resolved.IsIP() || resolved.IP() != target.IP() {
					t.Fatalf("resolved target = %v, want %v", resolved, target)
				}
				return
			}
			if !errors.Is(err, router.ErrRejected) {
				t.Fatalf("rejected target error = %v, want ErrRejected", err)
			}
		})
	}
}

func TestOutboundACLProtectsControlPlaneLocalAndInjectedTargets(t *testing.T) {
	resolver := &staticIPResolver{answers: map[string][][]netip.Addr{
		"allowed.example": {{netip.MustParseAddr("8.8.4.4")}},
		"private.example": {{netip.MustParseAddr("10.1.2.3")}},
		"local.example":   {{netip.MustParseAddr("93.184.216.34")}},
	}}
	local := &net.IPNet{IP: net.ParseIP("93.184.216.34"), Mask: net.CIDRMask(32, 32)}
	acl, err := newOutboundACLWithDependencies(
		"https://Panel.Example./api/v1",
		[]netip.Prefix{netip.MustParsePrefix("8.8.8.0/24")},
		resolver,
		func() ([]net.Addr, error) { return []net.Addr{local}, nil },
	)
	if err != nil {
		t.Fatal(err)
	}

	for _, target := range []conn.Addr{
		conn.MustAddrFromDomainPort("PANEL.EXAMPLE", 443),
		conn.MustAddrFromDomainPort("panel.example.", 443),
		conn.MustAddrFromDomainPort("private.example", 443),
		conn.MustAddrFromDomainPort("local.example", 443),
		conn.AddrFromIPAndPort(netip.MustParseAddr("8.8.8.8"), 53),
		conn.AddrFromIPAndPort(netip.MustParseAddr("93.184.216.34"), 443),
	} {
		if _, err := acl.ResolveAndAuthorize(t.Context(), target); !errors.Is(err, router.ErrRejected) {
			t.Fatalf("target %v error = %v, want ErrRejected", target, err)
		}
	}

	resolved, err := acl.ResolveAndAuthorize(t.Context(), conn.MustAddrFromDomainPort("allowed.example", 443))
	if err != nil {
		t.Fatalf("allowed domain rejected: %v", err)
	}
	if !resolved.IsIP() || resolved.IP() != netip.MustParseAddr("8.8.4.4") {
		t.Fatalf("allowed domain resolved to %v", resolved)
	}
}

func TestOutboundACLProtectsLiteralControlPlane(t *testing.T) {
	acl, err := newOutboundACLWithDependencies(
		"https://8.8.8.8/api/v1",
		nil,
		&staticIPResolver{},
		emptyInterfaceAddrs,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = acl.ResolveAndAuthorize(t.Context(), conn.AddrFromIPAndPort(netip.MustParseAddr("8.8.8.8"), 443))
	if !errors.Is(err, router.ErrRejected) {
		t.Fatalf("literal control-plane error = %v, want ErrRejected", err)
	}
}

func TestOutboundACLPinsEachCheckedDNSAnswer(t *testing.T) {
	resolver := &staticIPResolver{answers: map[string][][]netip.Addr{
		"rebind.example": {
			{netip.MustParseAddr("8.8.8.8")},
			{netip.MustParseAddr("127.0.0.1")},
		},
	}}
	acl := newTestOutboundACL(t, resolver)
	target := conn.MustAddrFromDomainPort("rebind.example", 443)

	first, err := acl.ResolveAndAuthorize(t.Context(), target)
	if err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	if !first.IsIP() || first.IP() != netip.MustParseAddr("8.8.8.8") {
		t.Fatalf("first lookup was not pinned to checked IP: %v", first)
	}
	if _, err := acl.ResolveAndAuthorize(t.Context(), target); !errors.Is(err, router.ErrRejected) {
		t.Fatalf("rebound private answer error = %v, want ErrRejected", err)
	}
}

func TestOutboundACLRecognizesEmbeddedIPv4(t *testing.T) {
	private := netip.MustParseAddr("10.1.2.3")
	mapped := netip.MustParseAddr("::ffff:10.1.2.3")
	if got, ok := embeddedIPv4(mapped); !ok || got != private {
		t.Fatalf("mapped extraction = %v, %v", got, ok)
	}

	metadata := netip.MustParseAddr("169.254.169.254")
	wkp := netip.MustParseAddr("64:ff9b::a9fe:a9fe")
	if got, ok := embeddedIPv4(wkp); !ok || got != metadata {
		t.Fatalf("well-known NAT64 extraction = %v, %v", got, ok)
	}

	b := localUseNAT64Prefix.Addr().As16()
	metadataBytes := metadata.As4()
	b[6], b[7], b[9], b[10] = metadataBytes[0], metadataBytes[1], metadataBytes[2], metadataBytes[3]
	localUse := netip.AddrFrom16(b)
	if got, ok := embeddedIPv4(localUse); !ok || got != metadata {
		t.Fatalf("local-use NAT64 extraction = %v, %v", got, ok)
	}
}

func TestOutboundACLInterfaceEnumerationFailureIsFatal(t *testing.T) {
	_, err := newOutboundACLWithDependencies(
		"https://panel.example",
		nil,
		&staticIPResolver{},
		func() ([]net.Addr, error) { return nil, errors.New("test failure") },
	)
	if err == nil {
		t.Fatal("interface enumeration failure was accepted")
	}
}
