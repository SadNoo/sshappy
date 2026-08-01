package flyskynode

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strings"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/router"
)

// ipResolver is kept small so policy behavior, including DNS rebinding
// protection, can be tested without using the host resolver.
type ipResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

// outboundACL is the default consumer-node egress policy. The first release is
// IPv4-only and denies special-purpose networks, host-local targets, the exact
// control-plane host, and explicitly injected protected prefixes.
//
// A successful domain lookup is returned as an IP target. This is essential:
// the direct TCP/UDP client must not resolve the name again after the policy
// check, otherwise DNS rebinding could change an allowed public address into a
// protected address between authorization and use.
type outboundACL struct {
	resolver             ipResolver
	controlPlaneHostname string
	protectedPrefixes    []netip.Prefix
}

var (
	blockedIPv4Prefixes = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("192.88.99.0/24"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("240.0.0.0/4"),
	}
	wellKnownNAT64Prefix = netip.MustParsePrefix("64:ff9b::/96")
	localUseNAT64Prefix  = netip.MustParsePrefix("64:ff9b:1::/48")
)

func newOutboundACL(controlPlaneURL string, protectedPrefixes []netip.Prefix) (*outboundACL, error) {
	return newOutboundACLWithDependencies(
		controlPlaneURL,
		protectedPrefixes,
		net.DefaultResolver,
		net.InterfaceAddrs,
	)
}

func newOutboundACLWithDependencies(
	controlPlaneURL string,
	protectedPrefixes []netip.Prefix,
	resolver ipResolver,
	interfaceAddrs func() ([]net.Addr, error),
) (*outboundACL, error) {
	if resolver == nil {
		return nil, errors.New("outbound ACL resolver is unavailable")
	}
	u, err := url.Parse(controlPlaneURL)
	if err != nil {
		return nil, errors.New("invalid control-plane URL for outbound ACL")
	}
	controlHost := canonicalHostname(u.Hostname())
	if controlHost == "" {
		return nil, errors.New("control-plane URL has no hostname for outbound ACL")
	}

	acl := &outboundACL{
		resolver:             resolver,
		controlPlaneHostname: controlHost,
		protectedPrefixes:    make([]netip.Prefix, 0, len(protectedPrefixes)+8),
	}
	for _, prefix := range protectedPrefixes {
		if err := acl.addProtectedPrefix(prefix); err != nil {
			return nil, err
		}
	}

	if controlIP, parseErr := netip.ParseAddr(controlHost); parseErr == nil {
		if err := acl.addProtectedIP(controlIP); err != nil {
			return nil, err
		}
	}

	if interfaceAddrs == nil {
		return nil, errors.New("outbound ACL interface address source is unavailable")
	}
	addrs, err := interfaceAddrs()
	if err != nil {
		return nil, errors.New("enumerate local interfaces for outbound ACL")
	}
	for _, addr := range addrs {
		if ip, ok := interfaceIP(addr); ok {
			if err := acl.addProtectedIP(ip); err != nil {
				return nil, err
			}
		}
	}
	return acl, nil
}

// ResolveAndAuthorize implements service.OutboundTargetPolicy.
func (a *outboundACL) ResolveAndAuthorize(ctx context.Context, target conn.Addr) (conn.Addr, error) {
	if !target.IsValid() {
		return conn.Addr{}, router.ErrRejected
	}

	if target.IsIP() {
		ip := target.IP()
		if !a.allowIP(ip) {
			return conn.Addr{}, router.ErrRejected
		}
		return conn.AddrFromIPAndPort(ip, target.Port()), nil
	}

	hostname := canonicalHostname(target.Domain())
	if hostname == "" || hostname == a.controlPlaneHostname {
		return conn.Addr{}, router.ErrRejected
	}
	resolved, err := a.resolver.LookupNetIP(ctx, "ip4", hostname)
	if err != nil {
		return conn.Addr{}, err
	}
	if len(resolved) == 0 {
		return conn.Addr{}, errors.New("outbound target resolved without addresses")
	}

	// Use exactly the address that was checked. The service wrapper passes this
	// IP target to the socket dialer/packet packer, preventing a second lookup.
	ip := resolved[0]
	if !a.allowIP(ip) {
		return conn.Addr{}, router.ErrRejected
	}
	return conn.AddrFromIPAndPort(ip, target.Port()), nil
}

func (a *outboundACL) allowIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}

	// IPv4-mapped IPv6 and the standard NAT64 forms are recognized before the
	// first-release IPv6 deny. They remain denied even when the embedded IPv4 is
	// public, so an alternate IPv6 representation cannot bypass IPv4-only mode.
	if ip.Is4In6() {
		_, _ = embeddedIPv4(ip)
		return false
	}
	if ip.Is6() {
		_, _ = embeddedIPv4(ip)
		return false
	}
	if !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, prefix := range blockedIPv4Prefixes {
		if prefix.Contains(ip) {
			return false
		}
	}
	for _, prefix := range a.protectedPrefixes {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

func (a *outboundACL) addProtectedIP(ip netip.Addr) error {
	if !ip.IsValid() {
		return errors.New("invalid protected outbound IP")
	}
	bits := ip.BitLen()
	if ip.Is4In6() {
		ip = ip.Unmap()
		bits = 32
	}
	return a.addProtectedPrefix(netip.PrefixFrom(ip, bits))
}

func (a *outboundACL) addProtectedPrefix(prefix netip.Prefix) error {
	normalized, err := normalizeProtectedEgressPrefix(prefix)
	if err != nil {
		return errors.New("invalid protected outbound prefix")
	}
	a.protectedPrefixes = append(a.protectedPrefixes, normalized)
	return nil
}

func canonicalHostname(host string) string {
	return strings.ToLower(strings.TrimRight(strings.TrimSpace(host), "."))
}

func interfaceIP(addr net.Addr) (netip.Addr, bool) {
	if addr == nil {
		return netip.Addr{}, false
	}
	switch value := addr.(type) {
	case *net.IPNet:
		ip, ok := netip.AddrFromSlice(value.IP)
		return ip, ok
	case *net.IPAddr:
		ip, ok := netip.AddrFromSlice(value.IP)
		return ip, ok
	}
	prefix, err := netip.ParsePrefix(addr.String())
	if err != nil {
		return netip.Addr{}, false
	}
	return prefix.Addr(), true
}

// embeddedIPv4 recognizes representations that can otherwise obscure an IPv4
// destination. The first release rejects all of these IPv6 forms, but keeping
// the extraction explicit makes the policy testable and prevents a later IPv6
// rollout from accidentally treating embedded private/metadata addresses as
// ordinary public IPv6.
func embeddedIPv4(ip netip.Addr) (netip.Addr, bool) {
	if ip.Is4In6() {
		return ip.Unmap(), true
	}
	if !ip.Is6() {
		return netip.Addr{}, false
	}
	b := ip.As16()
	switch {
	case wellKnownNAT64Prefix.Contains(ip):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case localUseNAT64Prefix.Contains(ip):
		// RFC 6052 /48 layout: 16 IPv4 bits before the reserved u octet,
		// then the remaining 16 IPv4 bits after it.
		return netip.AddrFrom4([4]byte{b[6], b[7], b[9], b[10]}), true
	default:
		return netip.Addr{}, false
	}
}
