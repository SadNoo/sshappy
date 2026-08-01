package service

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync/atomic"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/netio"
	"github.com/database64128/shadowsocks-go/router"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

// ErrOutboundPolicyResolution classifies resolver failures raised while an
// outbound target policy is pinning a domain to authorized IP candidates.
// Relays account for this error in aggregate instead of logging a user and
// target for every failed TCP attempt or UDP packet.
var ErrOutboundPolicyResolution = errors.New("outbound target policy resolution failed")

// OutboundTargetPolicy resolves and authorizes an outbound target before the
// target is handed to a direct network client. Implementations must return
// only IP targets so the authorization decision and the subsequent dial/send
// cannot be separated by another DNS lookup. A domain can yield more than one
// candidate; each returned address must have been checked independently.
type OutboundTargetPolicy interface {
	ResolveAndAuthorize(context.Context, conn.Addr) ([]conn.Addr, error)
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
	return d.dialStreamAfterAuthorize(ctx, target, payload, nil)
}

// dialStreamAfterAuthorize lets the authenticated relay reserve quota only
// after DNS pinning and the outbound ACL have accepted the target. A denied or
// unresolved target therefore never temporarily consumes a user's shared
// allowance while another legitimate connection is trying to reserve it.
func (d *policyStreamDialer) dialStreamAfterAuthorize(
	ctx context.Context,
	target conn.Addr,
	payload []byte,
	afterAuthorize func() error,
) (netio.Conn, error) {
	candidates, err := d.policy.ResolveAndAuthorize(ctx, canonicalOutboundTarget(target))
	if err != nil {
		return nil, err
	}
	if len(candidates) == 0 {
		return nil, ErrOutboundPolicyResolution
	}
	if afterAuthorize != nil {
		if err := afterAuthorize(); err != nil {
			return nil, err
		}
	}

	// Keep resolver order and try every independently authorized, already
	// pinned IP. A blocked or unreachable first A record must not prevent a
	// later public address from being used, and the direct dialer never sees the
	// original hostname (so it cannot perform a second lookup).
	var lastErr error
	for _, candidate := range candidates {
		remoteConn, dialErr := d.inner.DialStream(ctx, candidate, payload)
		if dialErr == nil {
			return remoteConn, nil
		}
		lastErr = dialErr
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, lastErr
}

type streamDialerAfterAuthorize interface {
	dialStreamAfterAuthorize(context.Context, conn.Addr, []byte, func() error) (netio.Conn, error)
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

// policyClientPacker passes only authorized IP targets to the direct packet
// packer. DNS caching and lookup de-duplication belong to the policy because a
// policy instance is shared by sessions. The packer deliberately uses the
// first candidate throughout one positive-cache generation: rotating the
// remote IP per packet would change the 5-tuple and break QUIC/UDP sessions.
type policyClientPacker struct {
	inner  zerocopy.ClientPacker
	policy OutboundTargetPolicy
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
	candidates, err := p.policy.ResolveAndAuthorize(ctx, canonicalOutboundTarget(target))
	if err != nil {
		return conn.Addr{}, err
	}
	if len(candidates) == 0 {
		return conn.Addr{}, ErrOutboundPolicyResolution
	}
	return candidates[0], nil
}

func canonicalOutboundTarget(target conn.Addr) conn.Addr {
	if !target.IsDomain() {
		return target
	}
	domain := strings.ToLower(strings.TrimRight(strings.TrimSpace(target.Domain()), "."))
	canonical, err := conn.AddrFromDomainPort(domain, target.Port())
	if err != nil {
		return conn.Addr{}
	}
	return canonical
}

func recordOutboundPolicyDrop(err error, denied, resolution *atomic.Uint64) bool {
	switch {
	case errors.Is(err, router.ErrRejected):
		denied.Add(1)
		return true
	case errors.Is(err, ErrOutboundPolicyResolution):
		resolution.Add(1)
		return true
	default:
		return false
	}
}
