package service

import (
	"context"
	"net/netip"
	"sync"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/netio"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

// OutboundTargetPolicy resolves and authorizes an outbound target before the
// target is handed to a direct network client. Implementations must return an
// IP target so the authorization decision and the subsequent dial/send cannot
// be separated by another DNS lookup.
type OutboundTargetPolicy interface {
	ResolveAndAuthorize(context.Context, conn.Addr) (conn.Addr, error)
}

type policyStreamClient struct {
	inner  netio.StreamClient
	policy OutboundTargetPolicy
}

func wrapStreamClient(inner netio.StreamClient, policy OutboundTargetPolicy) netio.StreamClient {
	if policy == nil {
		return inner
	}
	return &policyStreamClient{inner: inner, policy: policy}
}

func (c *policyStreamClient) NewStreamDialer() (netio.StreamDialer, netio.StreamDialerInfo) {
	dialer, info := c.inner.NewStreamDialer()
	return &policyStreamDialer{inner: dialer, policy: c.policy}, info
}

func (c *policyStreamClient) DialStream(ctx context.Context, target conn.Addr, payload []byte) (netio.Conn, error) {
	return (&policyStreamDialer{inner: c.inner, policy: c.policy}).DialStream(ctx, target, payload)
}

type policyStreamDialer struct {
	inner  netio.StreamDialer
	policy OutboundTargetPolicy
}

func (d *policyStreamDialer) DialStream(ctx context.Context, target conn.Addr, payload []byte) (netio.Conn, error) {
	resolved, err := d.policy.ResolveAndAuthorize(ctx, target)
	if err != nil {
		return nil, err
	}
	return d.inner.DialStream(ctx, resolved, payload)
}

type policyUDPClient struct {
	inner  zerocopy.UDPClient
	policy OutboundTargetPolicy
}

func wrapUDPClient(inner zerocopy.UDPClient, policy OutboundTargetPolicy) zerocopy.UDPClient {
	if policy == nil {
		return inner
	}
	return &policyUDPClient{inner: inner, policy: policy}
}

func (c *policyUDPClient) Info() zerocopy.UDPClientInfo {
	return c.inner.Info()
}

func (c *policyUDPClient) NewSession(ctx context.Context) (zerocopy.UDPClientSessionInfo, zerocopy.UDPClientSession, error) {
	info, session, err := c.inner.NewSession(ctx)
	if err != nil {
		return info, session, err
	}
	session.Packer = &policyClientPacker{inner: session.Packer, policy: c.policy}
	return info, session, nil
}

// policyClientPacker pins the most recently used domain to the authorized IP
// for the lifetime of this UDP client session. Other domains are always
// resolved and checked again; an authorization decision is never followed by
// a second resolver lookup in the direct packet packer.
type policyClientPacker struct {
	inner  zerocopy.ClientPacker
	policy OutboundTargetPolicy

	mu             sync.Mutex
	cachedDomain   string
	cachedIPTarget conn.Addr
}

func (p *policyClientPacker) ClientPackerInfo() zerocopy.ClientPackerInfo {
	return p.inner.ClientPackerInfo()
}

func (p *policyClientPacker) PackInPlace(
	ctx context.Context,
	b []byte,
	target conn.Addr,
	payloadStart, payloadLen int,
) (destAddrPort netip.AddrPort, packetStart, packetLen int, err error) {
	resolved, err := p.resolveAndAuthorize(ctx, target)
	if err != nil {
		return netip.AddrPort{}, 0, 0, err
	}
	return p.inner.PackInPlace(ctx, b, resolved, payloadStart, payloadLen)
}

func (p *policyClientPacker) resolveAndAuthorize(ctx context.Context, target conn.Addr) (conn.Addr, error) {
	if !target.IsDomain() {
		return p.policy.ResolveAndAuthorize(ctx, target)
	}

	domain := target.Domain()
	p.mu.Lock()
	if domain == p.cachedDomain {
		cached := p.cachedIPTarget
		p.mu.Unlock()
		return conn.AddrFromIPAndPort(cached.IP(), target.Port()), nil
	}
	p.mu.Unlock()

	resolved, err := p.policy.ResolveAndAuthorize(ctx, target)
	if err != nil {
		return conn.Addr{}, err
	}

	p.mu.Lock()
	p.cachedDomain = domain
	p.cachedIPTarget = resolved
	p.mu.Unlock()
	return resolved, nil
}
