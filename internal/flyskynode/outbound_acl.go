package flyskynode

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/router"
	"github.com/database64128/shadowsocks-go/service"
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
	nodeDNSUpstreams     []netip.Addr
	nodeDNSUpstreamSet   map[netip.Addr]struct{}
	now                  func() time.Time

	dnsMu       sync.Mutex
	dnsCache    map[string]outboundDNSCacheEntry
	dnsInflight map[string]*outboundDNSLookup
	dnsSequence uint64
}

type outboundDNSCacheEntry struct {
	addresses []netip.Addr
	err       error
	expiresAt time.Time
	lastUsed  uint64
}

type outboundDNSLookup struct {
	done      chan struct{}
	addresses []netip.Addr
	err       error
}

const (
	outboundDNSPositiveTTL   = 30 * time.Second
	outboundDNSNegativeTTL   = 5 * time.Second
	outboundDNSLookupTimeout = 5 * time.Second
	outboundDNSCacheMax      = 256
	outboundDNSInflightMax   = 256
	maximumNodeDNSUpstreams  = 4
	systemResolverConfigPath = "/etc/resolv.conf"
)

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
	wellKnownNAT64Prefix  = netip.MustParsePrefix("64:ff9b::/96")
	localUseNAT64Prefix   = netip.MustParsePrefix("64:ff9b:1::/48")
	nodeDNSVirtualAddress = netip.MustParseAddr("198.18.0.53")
)

func newOutboundACL(controlPlaneURL string, protectedPrefixes []netip.Prefix) (*outboundACL, error) {
	dnsUpstreams, err := readSystemDNSUpstreams(systemResolverConfigPath)
	if err != nil {
		return nil, err
	}
	return newOutboundACLWithDNSDependencies(
		controlPlaneURL,
		protectedPrefixes,
		net.DefaultResolver,
		net.InterfaceAddrs,
		dnsUpstreams,
	)
}

func newOutboundACLWithDependencies(
	controlPlaneURL string,
	protectedPrefixes []netip.Prefix,
	resolver ipResolver,
	interfaceAddrs func() ([]net.Addr, error),
) (*outboundACL, error) {
	return newOutboundACLWithDNSDependencies(
		controlPlaneURL, protectedPrefixes, resolver, interfaceAddrs, nil,
	)
}

func newOutboundACLWithDNSDependencies(
	controlPlaneURL string,
	protectedPrefixes []netip.Prefix,
	resolver ipResolver,
	interfaceAddrs func() ([]net.Addr, error),
	dnsUpstreams []netip.Addr,
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
		nodeDNSUpstreams:     make([]netip.Addr, 0, len(dnsUpstreams)),
		nodeDNSUpstreamSet:   make(map[netip.Addr]struct{}, len(dnsUpstreams)),
		now:                  time.Now,
		dnsCache:             make(map[string]outboundDNSCacheEntry),
		dnsInflight:          make(map[string]*outboundDNSLookup),
	}
	for _, upstream := range dnsUpstreams {
		upstream = upstream.Unmap()
		if !validNodeDNSUpstream(upstream) {
			return nil, errors.New("invalid node DNS upstream")
		}
		if _, exists := acl.nodeDNSUpstreamSet[upstream]; exists {
			continue
		}
		if len(acl.nodeDNSUpstreams) >= maximumNodeDNSUpstreams {
			break
		}
		acl.nodeDNSUpstreamSet[upstream] = struct{}{}
		acl.nodeDNSUpstreams = append(acl.nodeDNSUpstreams, upstream)
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
func (a *outboundACL) ResolveAndAuthorize(ctx context.Context, target conn.Addr) ([]conn.Addr, error) {
	if !target.IsValid() {
		return nil, router.ErrRejected
	}

	if target.IsIP() {
		ip := target.IP()
		if ip.Unmap() == nodeDNSVirtualAddress && target.Port() == 53 {
			if len(a.nodeDNSUpstreams) == 0 {
				return nil, router.ErrRejected
			}
			resolved := make([]conn.Addr, 0, len(a.nodeDNSUpstreams))
			for _, upstream := range a.nodeDNSUpstreams {
				resolved = append(resolved, conn.AddrFromIPAndPort(upstream, 53))
			}
			return resolved, nil
		}
		if !a.allowIP(ip) {
			return nil, router.ErrRejected
		}
		return []conn.Addr{conn.AddrFromIPAndPort(ip, target.Port())}, nil
	}

	hostname := canonicalHostname(target.Domain())
	if hostname == "" || hostname == a.controlPlaneHostname {
		return nil, router.ErrRejected
	}
	resolved, err := a.lookupIPv4(ctx, hostname)
	if err != nil {
		return nil, err
	}

	// Check every resolver answer, preserve its order, and skip protected or
	// duplicate candidates. A mixed answer set remains usable through its
	// public addresses; no unchecked hostname is ever passed to the dialer.
	candidates := make([]conn.Addr, 0, len(resolved))
	seen := make(map[netip.Addr]struct{}, len(resolved))
	for _, ip := range resolved {
		if !a.allowIP(ip) {
			continue
		}
		ip = ip.Unmap()
		if _, exists := seen[ip]; exists {
			continue
		}
		seen[ip] = struct{}{}
		candidates = append(candidates, conn.AddrFromIPAndPort(ip, target.Port()))
	}
	if len(candidates) == 0 {
		return nil, router.ErrRejected
	}
	return candidates, nil
}

// ResponseSourceRewrite opts into restoring the tunnel-only DNS virtual
// address only when this packet was originally addressed to that exact
// virtual endpoint and was authorized to an exact system resolver.
func (a *outboundACL) ResponseSourceRewrite(originalTarget, authorizedTarget conn.Addr) (netip.AddrPort, bool) {
	if !originalTarget.IsIP() || originalTarget.IP().Unmap() != nodeDNSVirtualAddress || originalTarget.Port() != 53 ||
		!authorizedTarget.IsIP() || authorizedTarget.Port() != 53 {
		return netip.AddrPort{}, false
	}
	if _, ok := a.nodeDNSUpstreamSet[authorizedTarget.IP().Unmap()]; !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(nodeDNSVirtualAddress, 53), true
}

func readSystemDNSUpstreams(path string) ([]netip.Addr, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open node system resolver configuration")
	}
	defer file.Close()
	upstreams, err := parseSystemDNSUpstreams(file)
	if err != nil {
		return nil, err
	}
	if len(upstreams) == 0 {
		return nil, errors.New("node system resolver configuration has no usable IPv4 nameserver")
	}
	return upstreams, nil
}

func parseSystemDNSUpstreams(reader io.Reader) ([]netip.Addr, error) {
	if reader == nil {
		return nil, errors.New("node system resolver configuration is unavailable")
	}
	scanner := bufio.NewScanner(reader)
	upstreams := make([]netip.Addr, 0, 2)
	seen := make(map[netip.Addr]struct{}, 2)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		upstream, err := netip.ParseAddr(fields[1])
		if err != nil {
			continue
		}
		upstream = upstream.Unmap()
		if !validNodeDNSUpstream(upstream) {
			continue
		}
		if _, exists := seen[upstream]; exists {
			continue
		}
		seen[upstream] = struct{}{}
		upstreams = append(upstreams, upstream)
		if len(upstreams) == maximumNodeDNSUpstreams {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.New("read node system resolver configuration")
	}
	return upstreams, nil
}

func validNodeDNSUpstream(ip netip.Addr) bool {
	if !ip.IsValid() || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip == nodeDNSVirtualAddress {
		return false
	}
	// Loopback, RFC1918 and CGNAT resolvers are allowed only through the exact
	// virtual DNS mapping. Direct proxy access to these addresses remains
	// blocked by allowIP.
	if ip.IsLoopback() || ip.IsPrivate() ||
		netip.MustParsePrefix("100.64.0.0/10").Contains(ip) ||
		netip.MustParsePrefix("198.18.0.0/15").Contains(ip) {
		return true
	}
	if !ip.IsGlobalUnicast() {
		return false
	}
	for _, prefix := range blockedIPv4Prefixes {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

// lookupIPv4 provides a small, shared positive and negative DNS cache. It
// deliberately owns the resolver call rather than leaving it to a socket
// dialer: that both prevents DNS rebinding and avoids per-packet lookups for
// UDP domain targets. Concurrent misses for the same canonical hostname share
// one lookup; the global in-flight cap bounds random-domain amplification.
func (a *outboundACL) lookupIPv4(ctx context.Context, hostname string) ([]netip.Addr, error) {
	hostname = canonicalHostname(hostname)
	if hostname == "" {
		return nil, router.ErrRejected
	}

	now := a.now()
	a.dnsMu.Lock()
	if cached, ok := a.dnsCache[hostname]; ok {
		if now.Before(cached.expiresAt) {
			a.dnsSequence++
			cached.lastUsed = a.dnsSequence
			a.dnsCache[hostname] = cached
			addresses := append([]netip.Addr(nil), cached.addresses...)
			a.dnsMu.Unlock()
			return addresses, cached.err
		}
		delete(a.dnsCache, hostname)
	}
	if lookup, ok := a.dnsInflight[hostname]; ok {
		a.dnsMu.Unlock()
		return waitOutboundDNSLookup(ctx, lookup)
	}
	if len(a.dnsInflight) >= outboundDNSInflightMax {
		a.dnsMu.Unlock()
		return nil, service.ErrOutboundPolicyResolution
	}
	lookup := &outboundDNSLookup{done: make(chan struct{})}
	a.dnsInflight[hostname] = lookup
	a.dnsMu.Unlock()

	go a.resolveIPv4(hostname, lookup)
	return waitOutboundDNSLookup(ctx, lookup)
}

func waitOutboundDNSLookup(ctx context.Context, lookup *outboundDNSLookup) ([]netip.Addr, error) {
	select {
	case <-lookup.done:
		return append([]netip.Addr(nil), lookup.addresses...), lookup.err
	case <-ctx.Done():
		return nil, errors.Join(service.ErrOutboundPolicyResolution, ctx.Err())
	}
}

func (a *outboundACL) resolveIPv4(hostname string, lookup *outboundDNSLookup) {
	lookupCtx, cancel := context.WithTimeout(context.Background(), outboundDNSLookupTimeout)
	addresses, err := a.resolver.LookupNetIP(lookupCtx, "ip4", hostname)
	cancel()
	if err != nil || len(addresses) == 0 {
		addresses = nil
		err = service.ErrOutboundPolicyResolution
	} else {
		addresses = append([]netip.Addr(nil), addresses...)
		err = nil
	}

	now := a.now()
	ttl := outboundDNSPositiveTTL
	if err != nil {
		ttl = outboundDNSNegativeTTL
	}

	a.dnsMu.Lock()
	lookup.addresses = addresses
	lookup.err = err
	a.insertDNSCacheLocked(hostname, outboundDNSCacheEntry{
		addresses: append([]netip.Addr(nil), addresses...),
		err:       err,
		expiresAt: now.Add(ttl),
	})
	delete(a.dnsInflight, hostname)
	close(lookup.done)
	a.dnsMu.Unlock()
}

func (a *outboundACL) insertDNSCacheLocked(hostname string, entry outboundDNSCacheEntry) {
	now := a.now()
	for key, cached := range a.dnsCache {
		if !now.Before(cached.expiresAt) {
			delete(a.dnsCache, key)
		}
	}
	if _, exists := a.dnsCache[hostname]; !exists && len(a.dnsCache) >= outboundDNSCacheMax {
		var oldestKey string
		var oldestSequence uint64
		first := true
		for key, cached := range a.dnsCache {
			if first || cached.lastUsed < oldestSequence {
				oldestKey = key
				oldestSequence = cached.lastUsed
				first = false
			}
		}
		delete(a.dnsCache, oldestKey)
	}
	a.dnsSequence++
	entry.lastUsed = a.dnsSequence
	a.dnsCache[hostname] = entry
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
