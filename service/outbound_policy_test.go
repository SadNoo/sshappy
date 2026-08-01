package service

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/netio"
	"github.com/database64128/shadowsocks-go/router"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

type testOutboundPolicy struct {
	resolved []netip.Addr
	err      error
	calls    int
	targets  []conn.Addr
}

func (p *testOutboundPolicy) ResolveAndAuthorize(_ context.Context, target conn.Addr) ([]conn.Addr, error) {
	p.calls++
	p.targets = append(p.targets, target)
	if p.err != nil {
		return nil, p.err
	}
	resolved := make([]conn.Addr, 0, len(p.resolved))
	for _, ip := range p.resolved {
		resolved = append(resolved, conn.AddrFromIPAndPort(ip, target.Port()))
	}
	return resolved, nil
}

type recordingStreamClient struct {
	targets []conn.Addr
	errs    []error
	before  func()
}

func (c *recordingStreamClient) NewStreamDialer() (netio.StreamDialer, netio.StreamDialerInfo) {
	return c, netio.StreamDialerInfo{Name: "recording", NativeInitialPayload: true}
}

func (c *recordingStreamClient) DialStream(_ context.Context, target conn.Addr, _ []byte) (netio.Conn, error) {
	if c.before != nil {
		c.before()
	}
	c.targets = append(c.targets, target)
	index := len(c.targets) - 1
	if index < len(c.errs) {
		return nil, c.errs[index]
	}
	return nil, nil
}

func TestPolicyStreamDialerCallsQuotaHookOnlyAfterAuthorization(t *testing.T) {
	authorized := false
	inner := &recordingStreamClient{before: func() {
		if !authorized {
			t.Error("inner dial happened before the post-authorization hook")
		}
	}}
	policy := &testOutboundPolicy{resolved: []netip.Addr{netip.MustParseAddr("203.0.113.10")}}
	dialer := &policyStreamDialer{inner: inner, policy: policy}
	if _, err := dialer.dialStreamAfterAuthorize(
		t.Context(), conn.MustAddrFromDomainPort("allowed.example", 443), nil,
		func() error { authorized = true; return nil },
	); err != nil {
		t.Fatal(err)
	}
	if !authorized || len(inner.targets) != 1 {
		t.Fatalf("authorized=%v targets=%v", authorized, inner.targets)
	}

	hookCalled := false
	denied := &policyStreamDialer{inner: inner, policy: &testOutboundPolicy{err: router.ErrRejected}}
	if _, err := denied.dialStreamAfterAuthorize(
		t.Context(), conn.MustAddrFromDomainPort("denied.example", 443), nil,
		func() error { hookCalled = true; return nil },
	); !errors.Is(err, router.ErrRejected) {
		t.Fatalf("denied dial error = %v", err)
	}
	if hookCalled {
		t.Fatal("denied target invoked the quota hook")
	}
}

func TestPolicyStreamClientPinsAuthorizedIP(t *testing.T) {
	inner := &recordingStreamClient{}
	policy := &testOutboundPolicy{resolved: []netip.Addr{netip.MustParseAddr("203.0.113.10")}}
	client := wrapStreamClient(inner, policy)
	target := conn.MustAddrFromDomainPort("destination.example", 443)

	if _, err := client.DialStream(t.Context(), target, nil); err != nil {
		t.Fatalf("DialStream: %v", err)
	}
	if got := inner.targets[0]; !got.IsIP() || got.IP() != policy.resolved[0] || got.Port() != 443 {
		t.Fatalf("inner client got unpinned target %v", got)
	}

	dialer, info := client.NewStreamDialer()
	if info.Name != "recording" || !info.NativeInitialPayload {
		t.Fatalf("dialer info changed: %+v", info)
	}
	if _, err := dialer.DialStream(t.Context(), target, nil); err != nil {
		t.Fatalf("dedicated DialStream: %v", err)
	}
	if policy.calls != 2 {
		t.Fatalf("policy calls = %d, want 2", policy.calls)
	}
}

func TestPolicyStreamClientPreservesRejection(t *testing.T) {
	inner := &recordingStreamClient{}
	client := wrapStreamClient(inner, &testOutboundPolicy{err: router.ErrRejected})

	_, err := client.DialStream(t.Context(), conn.MustAddrFromDomainPort("blocked.example", 80), nil)
	if !errors.Is(err, router.ErrRejected) {
		t.Fatalf("DialStream error = %v, want ErrRejected", err)
	}
	if len(inner.targets) != 0 {
		t.Fatalf("inner dialer was called for rejected target %v", inner.targets)
	}
}

func TestPolicyStreamClientTriesEveryPinnedCandidateInResolverOrder(t *testing.T) {
	inner := &recordingStreamClient{errs: []error{errors.New("first unreachable"), nil}}
	first := netip.MustParseAddr("203.0.113.10")
	second := netip.MustParseAddr("203.0.113.11")
	client := wrapStreamClient(inner, &testOutboundPolicy{resolved: []netip.Addr{first, second}})

	if _, err := client.DialStream(t.Context(), conn.MustAddrFromDomainPort("destination.example", 443), nil); err != nil {
		t.Fatalf("DialStream: %v", err)
	}
	if len(inner.targets) != 2 || inner.targets[0].IP() != first || inner.targets[1].IP() != second {
		t.Fatalf("dial targets = %v, want [%v %v]", inner.targets, first, second)
	}
}

type recordingUDPClient struct {
	packer *recordingClientPacker
}

func (c *recordingUDPClient) Info() zerocopy.UDPClientInfo {
	return zerocopy.UDPClientInfo{Name: "recording"}
}

func (c *recordingUDPClient) NewSession(context.Context) (zerocopy.UDPClientSessionInfo, zerocopy.UDPClientSession, error) {
	return zerocopy.UDPClientSessionInfo{Name: "recording", MTU: 1496}, zerocopy.UDPClientSession{
		MaxPacketSize: 1452,
		Packer:        c.packer,
		Unpacker:      recordingClientUnpacker{},
		Close:         zerocopy.NoopClose,
	}, nil
}

type recordingClientPacker struct {
	target conn.Addr
}

func (*recordingClientPacker) ClientPackerInfo() zerocopy.ClientPackerInfo {
	return zerocopy.ClientPackerInfo{}
}

func (p *recordingClientPacker) PackInPlace(_ context.Context, _ []byte, target conn.Addr, payloadStart, payloadLen int) (netip.AddrPort, int, int, error) {
	p.target = target
	return target.IPPort(), payloadStart, payloadLen, nil
}

type recordingClientUnpacker struct{}

func (recordingClientUnpacker) ClientUnpackerInfo() zerocopy.ClientUnpackerInfo {
	return zerocopy.ClientUnpackerInfo{}
}

func (recordingClientUnpacker) UnpackInPlace(_ []byte, source netip.AddrPort, packetStart, packetLen int) (netip.AddrPort, int, int, error) {
	return source, packetStart, packetLen, nil
}

func TestPolicyUDPClientPinsCanonicalDomainAndKeepsStableCandidate(t *testing.T) {
	innerPacker := &recordingClientPacker{}
	inner := &recordingUDPClient{packer: innerPacker}
	first := netip.MustParseAddr("203.0.113.20")
	second := netip.MustParseAddr("203.0.113.21")
	policy := &testOutboundPolicy{resolved: []netip.Addr{first, second}}
	client := wrapUDPClient(inner, policy)
	_, session, err := client.NewSession(t.Context())
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	target := conn.MustAddrFromDomainPort("udp.example", 443)

	for _, port := range []uint16{443, 443} {
		target = conn.MustAddrFromDomainPort("UDP.Example.", port)
		if _, _, _, err := session.Packer.PackInPlace(t.Context(), make([]byte, 32), target, 0, 32); err != nil {
			t.Fatalf("PackInPlace: %v", err)
		}
		if !innerPacker.target.IsIP() || innerPacker.target.IP() != first || innerPacker.target.Port() != port {
			t.Fatalf("inner packer got unpinned target %v", innerPacker.target)
		}
	}
	if policy.calls != 2 {
		t.Fatalf("policy calls = %d, want one policy decision per packet", policy.calls)
	}
	for _, policyTarget := range policy.targets {
		if !policyTarget.IsDomain() || policyTarget.Domain() != "udp.example" {
			t.Fatalf("policy target was not canonicalized: %v", policyTarget)
		}
	}
}

func TestPolicyUDPClientDoesNotPackRejectedTarget(t *testing.T) {
	innerPacker := &recordingClientPacker{}
	client := wrapUDPClient(&recordingUDPClient{packer: innerPacker}, &testOutboundPolicy{err: router.ErrRejected})
	_, session, err := client.NewSession(t.Context())
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	_, _, _, err = session.Packer.PackInPlace(
		t.Context(), make([]byte, 32), conn.MustAddrFromDomainPort("blocked.example", 53), 0, 32,
	)
	if !errors.Is(err, router.ErrRejected) {
		t.Fatalf("PackInPlace error = %v, want ErrRejected", err)
	}
	if innerPacker.target.IsValid() {
		t.Fatalf("inner packer was called for rejected target %v", innerPacker.target)
	}
}

func TestRecordOutboundPolicyDropUsesAggregateCounters(t *testing.T) {
	var denied atomic.Uint64
	var resolution atomic.Uint64
	if !recordOutboundPolicyDrop(router.ErrRejected, &denied, &resolution) {
		t.Fatal("policy denial was not classified")
	}
	if !recordOutboundPolicyDrop(ErrOutboundPolicyResolution, &denied, &resolution) {
		t.Fatal("policy resolution failure was not classified")
	}
	if recordOutboundPolicyDrop(errors.New("ordinary pack failure"), &denied, &resolution) {
		t.Fatal("ordinary pack failure was suppressed as a policy error")
	}
	if denied.Load() != 1 || resolution.Load() != 1 {
		t.Fatalf("aggregate counters = denied:%d resolution:%d", denied.Load(), resolution.Load())
	}
}
