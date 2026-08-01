package service

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"github.com/database64128/shadowsocks-go/conn"
)

type targetTestObserver struct {
	resolved conn.Addr
	accepted bool
	err      error
	called   bool
}

func (*targetTestObserver) Accept(string, string, netip.AddrPort, conn.Addr) bool { return true }

func (*targetTestObserver) Observe(string, string, netip.AddrPort) {}

func (o *targetTestObserver) ResolveAndAcceptTarget(_ context.Context, network, username string, source netip.AddrPort, target conn.Addr) (conn.Addr, bool, error) {
	o.called = network == "tcp" && username == "7" && source == netip.MustParseAddrPort("203.0.113.1:12345") && target.IsDomain()
	return o.resolved, o.accepted, o.err
}

type basicTargetTestObserver struct{}

func (basicTargetTestObserver) Accept(string, string, netip.AddrPort, conn.Addr) bool { return true }

func (basicTargetTestObserver) Observe(string, string, netip.AddrPort) {}

type cachingTargetTestObserver struct {
	domainCalls     int
	literalCalls    int
	literalAccepted bool
}

func (*cachingTargetTestObserver) Accept(string, string, netip.AddrPort, conn.Addr) bool {
	return true
}

func (*cachingTargetTestObserver) Observe(string, string, netip.AddrPort) {}

func (o *cachingTargetTestObserver) ResolveAndAcceptTarget(_ context.Context, _ string, _ string, _ netip.AddrPort, target conn.Addr) (conn.Addr, bool, error) {
	if target.IsIP() {
		o.literalCalls++
		return target, o.literalAccepted, nil
	}
	o.domainCalls++
	return conn.AddrFromIPAndPort(netip.MustParseAddr("203.0.113.9"), target.Port()), true, nil
}

func TestResolveRuntimeTargetUsesOptionalResolver(t *testing.T) {
	target := conn.MustAddrFromDomainPort("target.example", 80)
	resolved := conn.AddrFromIPAndPort(netip.MustParseAddr("203.0.113.9"), 80)
	observer := &targetTestObserver{resolved: resolved, accepted: true}

	got, accepted, err := resolveRuntimeTarget(
		t.Context(),
		observer,
		"tcp",
		"7",
		netip.MustParseAddrPort("203.0.113.1:12345"),
		target,
	)
	if err != nil || !accepted || !observer.called || !got.Equals(resolved) {
		t.Fatalf("resolved target = (%v, %v, %v), called=%v", got, accepted, err, observer.called)
	}
}

func TestResolveRuntimeTargetPreservesCompatibility(t *testing.T) {
	target := conn.MustAddrFromDomainPort("target.example", 80)
	got, accepted, err := resolveRuntimeTarget(
		t.Context(),
		basicTargetTestObserver{},
		"tcp",
		"7",
		netip.MustParseAddrPort("203.0.113.1:12345"),
		target,
	)
	if err != nil || !accepted || !got.Equals(target) {
		t.Fatalf("basic observer target = (%v, %v, %v)", got, accepted, err)
	}
}

func TestResolveRuntimeTargetPropagatesFailure(t *testing.T) {
	wantErr := errors.New("DNS unavailable")
	observer := &targetTestObserver{err: wantErr}
	_, accepted, err := resolveRuntimeTarget(
		t.Context(),
		observer,
		"tcp",
		"7",
		netip.MustParseAddrPort("203.0.113.1:12345"),
		conn.MustAddrFromDomainPort("target.example", 80),
	)
	if accepted || !errors.Is(err, wantErr) {
		t.Fatalf("failure = (accepted=%v, err=%v)", accepted, err)
	}
}

func TestRuntimeTargetCachePinsUDPDomainAndRechecksPolicy(t *testing.T) {
	observer := &cachingTargetTestObserver{literalAccepted: true}
	var cache runtimeTargetCache
	target := conn.MustAddrFromDomainPort("target.example", 1023)
	source := netip.MustParseAddrPort("203.0.113.1:12345")

	first, accepted, err := cache.resolveAndAccept(t.Context(), observer, "udp", "7", source, target)
	if err != nil || !accepted || !first.IsIP() {
		t.Fatalf("first resolution = (%v, %v, %v)", first, accepted, err)
	}
	second, accepted, err := cache.resolveAndAccept(t.Context(), observer, "udp", "7", source, target)
	if err != nil || !accepted || !second.Equals(first) {
		t.Fatalf("cached resolution = (%v, %v, %v), want %v", second, accepted, err, first)
	}
	if observer.domainCalls != 1 || observer.literalCalls != 1 {
		t.Fatalf("resolver calls = domain:%d literal:%d, want 1 and 1", observer.domainCalls, observer.literalCalls)
	}

	observer.literalAccepted = false
	_, accepted, err = cache.resolveAndAccept(t.Context(), observer, "udp", "7", source, target)
	if err != nil || accepted || observer.domainCalls != 1 {
		t.Fatalf("cached policy recheck = (accepted=%v, err=%v, domainCalls=%d)", accepted, err, observer.domainCalls)
	}
}

func TestRuntimeTargetCacheRejectsUnboundedUniqueDomains(t *testing.T) {
	observer := &cachingTargetTestObserver{literalAccepted: true}
	var cache runtimeTargetCache
	source := netip.MustParseAddrPort("203.0.113.1:12345")
	for i := range runtimeTargetCacheMaxEntries {
		target := conn.MustAddrFromDomainPort(fmt.Sprintf("target-%d.example", i), 1023)
		if _, accepted, err := cache.resolveAndAccept(t.Context(), observer, "udp", "7", source, target); err != nil || !accepted {
			t.Fatalf("cache entry %d = (accepted=%v, err=%v)", i, accepted, err)
		}
	}
	_, accepted, err := cache.resolveAndAccept(
		t.Context(),
		observer,
		"udp",
		"7",
		source,
		conn.MustAddrFromDomainPort("one-too-many.example", 1023),
	)
	if accepted || !errors.Is(err, errRuntimeTargetCacheFull) {
		t.Fatalf("cache overflow = (accepted=%v, err=%v)", accepted, err)
	}
	if observer.domainCalls != runtimeTargetCacheMaxEntries {
		t.Fatalf("domain resolutions = %d, want %d", observer.domainCalls, runtimeTargetCacheMaxEntries)
	}
}
