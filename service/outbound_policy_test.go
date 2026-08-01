package service

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/netio"
	"github.com/database64128/shadowsocks-go/router"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

type testOutboundPolicy struct {
	resolved netip.Addr
	err      error
	calls    int
}

func (p *testOutboundPolicy) ResolveAndAuthorize(_ context.Context, target conn.Addr) (conn.Addr, error) {
	p.calls++
	if p.err != nil {
		return conn.Addr{}, p.err
	}
	return conn.AddrFromIPAndPort(p.resolved, target.Port()), nil
}

type recordingStreamClient struct {
	target conn.Addr
}

func (c *recordingStreamClient) NewStreamDialer() (netio.StreamDialer, netio.StreamDialerInfo) {
	return c, netio.StreamDialerInfo{Name: "recording", NativeInitialPayload: true}
}

func (c *recordingStreamClient) DialStream(_ context.Context, target conn.Addr, _ []byte) (netio.Conn, error) {
	c.target = target
	return nil, nil
}

func TestPolicyStreamClientPinsAuthorizedIP(t *testing.T) {
	inner := &recordingStreamClient{}
	policy := &testOutboundPolicy{resolved: netip.MustParseAddr("203.0.113.10")}
	client := wrapStreamClient(inner, policy)
	target := conn.MustAddrFromDomainPort("destination.example", 443)

	if _, err := client.DialStream(t.Context(), target, nil); err != nil {
		t.Fatalf("DialStream: %v", err)
	}
	if !inner.target.IsIP() || inner.target.IP() != policy.resolved || inner.target.Port() != 443 {
		t.Fatalf("inner client got unpinned target %v", inner.target)
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
	if inner.target.IsValid() {
		t.Fatalf("inner dialer was called for rejected target %v", inner.target)
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

func TestPolicyUDPClientPinsAndCachesAuthorizedDomain(t *testing.T) {
	innerPacker := &recordingClientPacker{}
	inner := &recordingUDPClient{packer: innerPacker}
	policy := &testOutboundPolicy{resolved: netip.MustParseAddr("203.0.113.20")}
	client := wrapUDPClient(inner, policy)
	_, session, err := client.NewSession(t.Context())
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	target := conn.MustAddrFromDomainPort("udp.example", 443)

	for _, port := range []uint16{443, 8443} {
		target = conn.MustAddrFromDomainPort("udp.example", port)
		if _, _, _, err := session.Packer.PackInPlace(t.Context(), make([]byte, 32), target, 0, 32); err != nil {
			t.Fatalf("PackInPlace: %v", err)
		}
		if !innerPacker.target.IsIP() || innerPacker.target.IP() != policy.resolved || innerPacker.target.Port() != port {
			t.Fatalf("inner packer got unpinned target %v", innerPacker.target)
		}
	}
	if policy.calls != 1 {
		t.Fatalf("policy calls = %d, want one lookup for repeated domain", policy.calls)
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
