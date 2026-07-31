package dns

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"iter"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/database64128/shadowsocks-go/cache"
	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/netio"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	// maxDNSPacketSize is the maximum packet size to advertise in EDNS(0).
	// We use the same value as Go itself.
	maxDNSPacketSize = 1232

	lookupTimeout = 20 * time.Second

	// rcodeFailureCachingDuration is the duration to cache responses with
	// [dnsmessage.RCodeFormatError], [dnsmessage.RCodeServerFailure],
	// [dnsmessage.RCodeNotImplemented], [dnsmessage.RCodeRefused].
	//
	// RFC 9520 section 3.2 states that resolvers MUST cache resolution failures for [1s, 5min].
	rcodeFailureCachingDuration = 30 * time.Second

	defaultCacheSize = 1024
)

var (
	ErrLookup                       = errors.New("name lookup failed")
	ErrMessageNotResponse           = errors.New("message is not a response")
	ErrResponseNoRecursionAvailable = errors.New("response indicates server does not support recursion")
	ErrDomainNoAssociatedIPs        = errors.New("domain name has no associated IP addresses")
)

// ResolverConfig configures a DNS resolver.
type ResolverConfig struct {
	// Name is the resolver's name.
	// The name must be unique among all resolvers.
	Name string `json:"name"`

	// Type is the resolver type.
	//
	//  - "plain": Resolve names by sending cleartext DNS queries to the configured upstream server.
	//  - "system": Use the system resolver. This does not support custom server addresses or clients.
	//
	// The default value is "plain".
	Type string `json:"type,omitzero"`

	// AddrPort is the upstream server's address and port.
	AddrPort netip.AddrPort `json:"addrPort,omitzero"`

	// TCPClientName is the name of the TCPClient to use.
	// Leave empty to disable TCP.
	TCPClientName string `json:"tcpClientName,omitzero"`

	// UDPClientName is the name of the UDPClient to use.
	// Leave empty to disable UDP.
	UDPClientName string `json:"udpClientName,omitzero"`

	// CacheSize is the size of the DNS cache.
	//
	// If zero, the default cache size is 1024.
	// If negative, the cache will be unbounded.
	CacheSize int `json:"cacheSize,omitzero"`
}

// NewSimpleResolver creates a new [NewSimpleResolver] from the config.
func (rc *ResolverConfig) NewSimpleResolver(tcpClientMap map[string]netio.StreamClient, udpClientMap map[string]zerocopy.UDPClient, logger *zap.Logger) (SimpleResolver, error) {
	switch rc.Type {
	case "plain", "":
	case "system":
		if rc.AddrPort.IsValid() || rc.TCPClientName != "" || rc.UDPClientName != "" {
			return nil, errors.New("system resolver does not support custom server addresses or clients")
		}
		return NewSystemResolver(rc.Name, logger), nil
	default:
		return nil, fmt.Errorf("unknown resolver type: %q", rc.Type)
	}

	if !rc.AddrPort.IsValid() {
		return nil, errors.New("missing resolver address")
	}

	if rc.TCPClientName == "" && rc.UDPClientName == "" {
		return nil, errors.New("neither TCP nor UDP client specified")
	}

	var (
		tcpClient netio.StreamClient
		udpClient zerocopy.UDPClient
	)

	if rc.TCPClientName != "" {
		tcpClient = tcpClientMap[rc.TCPClientName]
		if tcpClient == nil {
			return nil, fmt.Errorf("unknown TCP client: %q", rc.TCPClientName)
		}
	}

	if rc.UDPClientName != "" {
		udpClient = udpClientMap[rc.UDPClientName]
		if udpClient == nil {
			return nil, fmt.Errorf("unknown UDP client: %q", rc.UDPClientName)
		}
	}

	cacheSize := rc.CacheSize
	if cacheSize == 0 {
		cacheSize = defaultCacheSize
	}

	return NewResolver(rc.Name, cacheSize, rc.AddrPort, tcpClient, udpClient, logger), nil
}

// Result represents the result of name resolution.
type Result struct {
	a         []netip.Addr
	aaaa      []netip.Addr
	expiresAt time.Time
}

// A returns an iterator over the IPv4 addresses in the result.
func (r *Result) A() iter.Seq[netip.Addr] {
	return slices.Values(r.a)
}

// AAAA returns an iterator over the IPv6 addresses in the result.
func (r *Result) AAAA() iter.Seq[netip.Addr] {
	return slices.Values(r.aaaa)
}

// HasExpired returns true if the result's TTL has expired.
func (r *Result) HasExpired() bool {
	return r.expiresAt.Before(time.Now())
}

type Resolver struct {
	// name stores the resolver's name to make its log messages more useful.
	name string

	// mu protects the DNS cache.
	mu sync.Mutex

	// cache is the DNS cache.
	cache cache.BoundedCache[string, Result]

	// serverAddr is the upstream server's address and port.
	serverAddr conn.Addr

	// serverAddrPort is the upstream server's address and port.
	serverAddrPort netip.AddrPort

	// tcpClient is the TCP client to use for sending queries and receiving replies.
	tcpClient netio.StreamClient

	// udpClient is the UDPClient to use for sending queries and receiving replies.
	udpClient zerocopy.UDPClient

	// logger is the shared logger instance.
	logger *zap.Logger
}

func NewResolver(name string, cacheSize int, serverAddrPort netip.AddrPort, tcpClient netio.StreamClient, udpClient zerocopy.UDPClient, logger *zap.Logger) *Resolver {
	return &Resolver{
		name:           name,
		cache:          *cache.NewBoundedCache[string, Result](cacheSize),
		serverAddr:     conn.AddrFromIPPort(serverAddrPort),
		serverAddrPort: serverAddrPort,
		tcpClient:      tcpClient,
		udpClient:      udpClient,
		logger:         logger,
	}
}

// Lookup looks up name's A and AAAA records and returns the result.
func (r *Resolver) Lookup(ctx context.Context, name string) (Result, error) {
	// Lookup cache first.
	r.mu.Lock()
	result, ok := r.cache.Get(name)
	r.mu.Unlock()

	if ok && !result.HasExpired() {
		if ce := r.logger.Check(zap.DebugLevel, "DNS lookup got result from cache"); ce != nil {
			ce.Write(
				zap.String("resolver", r.name),
				zap.String("name", name),
				zap.Time("ttl", result.expiresAt),
				zap.Stringers("v4", result.a),
				zap.Stringers("v6", result.aaaa),
			)
		}
		return result, nil
	}

	// Send queries to upstream server.

	var newResult resultBuilder
	if err := r.sendQueries(ctx, name, &newResult); err != nil {
		if ok {
			// RFC 8767 serve-stale
			r.logger.Warn("DNS lookup failed, returning expired cached result",
				zap.String("resolver", r.name),
				zap.String("name", name),
				zap.Time("ttl", result.expiresAt),
			)
			return result, nil
		}
		return Result{}, err
	}
	result = newResult.Result

	// Add result to cache.
	// Permit expired results for serve-stale.
	r.mu.Lock()
	r.cache.Set(name, result)
	r.mu.Unlock()

	return result, nil
}

func (r *Resolver) sendQueries(ctx context.Context, nameString string, result *resultBuilder) error {
	name, err := dnsmessage.NewName(nameString + ".")
	if err != nil {
		return err
	}

	var (
		rh dnsmessage.ResourceHeader
		rb dnsmessage.OPTResource
	)

	if err := rh.SetEDNS0(maxDNSPacketSize, dnsmessage.RCodeSuccess, false); err != nil {
		return err
	}

	qBuf := make([]byte, 2+512+2+512)

	q4ID, q6ID, err := randomTransactionIDs()
	if err != nil {
		return fmt.Errorf("failed to generate DNS transaction IDs: %w", err)
	}
	q4Question := dnsmessage.Question{
		Name:  name,
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}
	q6Question := dnsmessage.Question{
		Name:  name,
		Type:  dnsmessage.TypeAAAA,
		Class: dnsmessage.ClassINET,
	}
	result.q4 = dnsQuery{id: q4ID, question: q4Question}
	result.q6 = dnsQuery{id: q6ID, question: q6Question, ipv6: true}

	q4 := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               q4ID,
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{q4Question},
		Additionals: []dnsmessage.Resource{
			{
				Header: rh,
				Body:   &rb,
			},
		},
	}
	q4Pkt, err := q4.AppendPack(qBuf[2:2])
	if err != nil {
		return err
	}
	q4PktEnd := 2 + len(q4Pkt)

	q6 := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               q6ID,
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{q6Question},
		Additionals: []dnsmessage.Resource{
			{
				Header: rh,
				Body:   &rb,
			},
		},
	}
	q6PktStart := q4PktEnd + 2
	q6Pkt, err := q6.AppendPack(qBuf[q6PktStart:q6PktStart])
	if err != nil {
		return err
	}
	q6PktEnd := q6PktStart + len(q6Pkt)

	// Try UDP first if available.
	if r.udpClient != nil {
		r.sendQueriesUDP(ctx, nameString, q4Pkt, q6Pkt, result)

		if ce := r.logger.Check(zap.DebugLevel, "DNS lookup sent queries via UDP"); ce != nil {
			ce.Write(
				zap.String("resolver", r.name),
				zap.String("name", nameString),
				zap.Bool("handled", result.isDone()),
				zap.Stringers("v4", result.a),
				zap.Stringers("v6", result.aaaa),
				zap.Time("ttl", result.expiresAt),
			)
		}
	}

	// Fallback to TCP if UDP failed or is unavailable.
	if !result.isDone() && r.tcpClient != nil {
		// Write length fields.
		q4LenBuf := qBuf[:2]
		q6LenBuf := qBuf[q4PktEnd:q6PktStart]
		binary.BigEndian.PutUint16(q4LenBuf, uint16(len(q4Pkt)))
		binary.BigEndian.PutUint16(q6LenBuf, uint16(len(q6Pkt)))

		r.sendQueriesTCP(ctx, nameString, qBuf[:q6PktEnd], q4PktEnd, result)

		if ce := r.logger.Check(zap.DebugLevel, "DNS lookup sent queries via TCP"); ce != nil {
			ce.Write(
				zap.String("resolver", r.name),
				zap.String("name", nameString),
				zap.Bool("handled", result.isDone()),
				zap.Stringers("v4", result.a),
				zap.Stringers("v6", result.aaaa),
				zap.Time("ttl", result.expiresAt),
			)
		}
	}

	if !result.isDone() {
		return ErrLookup
	}

	return nil
}

func randomTransactionIDs() (q4ID, q6ID uint16, err error) {
	var ids [4]byte
	if _, err = rand.Read(ids[:]); err != nil {
		return 0, 0, err
	}
	q4ID = binary.BigEndian.Uint16(ids[:2])
	q6ID = binary.BigEndian.Uint16(ids[2:])
	if q4ID == q6ID {
		q6ID++
	}
	return q4ID, q6ID, nil
}

// sendQueriesUDP sends queries using the resolver's UDP client and returns the result and whether the lookup was successful.
func (r *Resolver) sendQueriesUDP(ctx context.Context, nameString string, q4Pkt, q6Pkt []byte, result *resultBuilder) {
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()

	clientInfo, clientSession, err := r.udpClient.NewSession(ctx)
	if err != nil {
		r.logger.Warn("Failed to create new UDP client session",
			zap.String("resolver", r.name),
			zap.String("client", clientInfo.Name),
			zap.String("name", nameString),
			zap.Error(err),
		)
		return
	}
	defer clientSession.Close()

	udpConn, _, err := clientInfo.ListenConfig.ListenUDP(ctx, "udp", "")
	if err != nil {
		r.logger.Warn("Failed to create UDP socket for DNS lookup",
			zap.String("resolver", r.name),
			zap.String("client", clientInfo.Name),
			zap.String("name", nameString),
			zap.Error(err),
		)
		return
	}
	defer udpConn.Close()

	stop := context.AfterFunc(ctx, func() {
		_ = udpConn.SetReadDeadline(conn.ALongTimeAgo)
	})
	defer stop()

	ctx4, cancel4 := context.WithCancel(ctx)
	ctx6, cancel6 := context.WithCancel(ctx)
	defer cancel4()
	defer cancel6()

	// A UDP session's packer may be stateful. Keep both A and AAAA sends on
	// one goroutine so a single packer is never used concurrently.
	sendFunc := func() {
		maxQueryLen := max(len(q4Pkt), len(q6Pkt))
		b := make([]byte, clientInfo.PackerHeadroom.Front+maxQueryLen+clientInfo.PackerHeadroom.Rear)
		isDone := func(done <-chan struct{}) bool {
			select {
			case <-done:
				return true
			default:
				return false
			}
		}
		send := func(pkt []byte, done <-chan struct{}) bool {
			if isDone(done) {
				return true
			}
			copy(b[clientInfo.PackerHeadroom.Front:], pkt)
			destAddrPort, packetStart, packetLength, err := clientSession.Packer.PackInPlace(ctx, b, r.serverAddr, clientInfo.PackerHeadroom.Front, len(pkt))
			if err != nil {
				if ctx.Err() != nil {
					return false
				}
				r.logger.Warn("Failed to pack UDP DNS query packet",
					zap.String("resolver", r.name),
					zap.String("client", clientInfo.Name),
					zap.String("name", nameString),
					zap.Stringer("serverAddrPort", r.serverAddrPort),
					zap.Error(err),
				)
				cancel()
				return false
			}

			_, err = udpConn.WriteToUDPAddrPort(b[packetStart:packetStart+packetLength], destAddrPort)
			if err != nil {
				if ctx.Err() != nil {
					return false
				}
				r.logger.Warn("Failed to write UDP DNS query packet",
					zap.String("resolver", r.name),
					zap.String("client", clientInfo.Name),
					zap.String("name", nameString),
					zap.Stringer("serverAddrPort", r.serverAddrPort),
					zap.Stringer("destAddrPort", destAddrPort),
					zap.Error(err),
				)
				cancel()
				return false
			}
			return true
		}

		for range 10 {
			if !send(q4Pkt, ctx4.Done()) || !send(q6Pkt, ctx6.Done()) {
				return
			}
			if isDone(ctx4.Done()) && isDone(ctx6.Done()) {
				return
			}
			timer := time.NewTimer(2 * time.Second)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return
			case <-timer.C:
			}
		}
	}

	senderDone := make(chan struct{})
	go func() {
		defer close(senderDone)
		sendFunc()
	}()
	// This defer is registered after the session/socket cleanup defers, so it
	// runs first. Do not close a potentially stateful UDP client session while
	// its packer is still executing in the sender goroutine.
	defer func() {
		cancel()
		<-senderDone
	}()

	// Receive replies.
	recvBuf := make([]byte, clientSession.MaxPacketSize)

	for {
		n, _, flags, packetSourceAddress, err := udpConn.ReadMsgUDPAddrPort(recvBuf, nil)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				r.logger.Warn("DNS lookup via UDP timed out",
					zap.String("resolver", r.name),
					zap.String("client", clientInfo.Name),
					zap.String("name", nameString),
					zap.Stringer("serverAddrPort", r.serverAddrPort),
				)
				break
			}
			r.logger.Warn("Failed to read UDP DNS response",
				zap.String("resolver", r.name),
				zap.String("client", clientInfo.Name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Stringer("packetSourceAddress", packetSourceAddress),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			continue
		}
		if err = conn.ParseFlagsForError(flags); err != nil {
			r.logger.Warn("Failed to read UDP DNS response",
				zap.String("resolver", r.name),
				zap.String("client", clientInfo.Name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Stringer("packetSourceAddress", packetSourceAddress),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			continue
		}

		payloadSourceAddrPort, payloadStart, payloadLength, err := clientSession.Unpacker.UnpackInPlace(recvBuf, packetSourceAddress, 0, n)
		if err != nil {
			r.logger.Warn("Failed to unpack UDP DNS response packet",
				zap.String("resolver", r.name),
				zap.String("client", clientInfo.Name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Stringer("packetSourceAddress", packetSourceAddress),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			continue
		}
		if !conn.AddrPortMappedEqual(payloadSourceAddrPort, r.serverAddrPort) {
			r.logger.Warn("Ignoring UDP DNS response packet from unknown server",
				zap.String("resolver", r.name),
				zap.String("client", clientInfo.Name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Stringer("payloadSourceAddrPort", payloadSourceAddrPort),
			)
			continue
		}
		msg := recvBuf[payloadStart : payloadStart+payloadLength]

		header, err := result.parseMsg(msg, true)
		if err != nil {
			r.logger.Warn("Failed to parse UDP DNS response",
				zap.String("resolver", r.name),
				zap.String("client", clientInfo.Name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Error(err),
			)
			continue
		}
		if header.Truncated {
			if ce := r.logger.Check(zap.DebugLevel, "Received truncated UDP DNS response"); ce != nil {
				ce.Write(
					zap.String("resolver", r.name),
					zap.String("client", clientInfo.Name),
					zap.String("name", nameString),
					zap.Stringer("serverAddrPort", r.serverAddrPort),
					zap.Uint16("transactionID", header.ID),
				)
			}
			// Immediately fall back to TCP.
			break
		}
		if header.RCode != dnsmessage.RCodeSuccess {
			r.logger.Warn("Received non-success UDP DNS response",
				zap.String("resolver", r.name),
				zap.String("client", clientInfo.Name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Uint16("transactionID", header.ID),
				zap.Stringer("rcode", header.RCode),
			)
		}

		// Break out of loop if both v4 and v6 are done.
		if result.isDone() {
			break
		}

		switch header.ID {
		case result.q4.id:
			cancel4()
		case result.q6.id:
			cancel6()
		}
	}
}

// sendQueriesTCP sends queries using the resolver's TCP client and returns the result and whether the lookup was successful.
func (r *Resolver) sendQueriesTCP(ctx context.Context, nameString string, queries []byte, q4PktEnd int, result *resultBuilder) {
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()

	dialer, clientInfo := r.tcpClient.NewStreamDialer()

	// Retry unanswered queries.
	for range 2 {
		b := queries
		switch {
		case result.v4done && result.v6done:
			return
		case result.v4done:
			b = b[q4PktEnd:]
		case result.v6done:
			b = b[:q4PktEnd]
		}
		if !r.doTCP(ctx, dialer, clientInfo, nameString, b, result) {
			return
		}
	}
}

func (r *Resolver) doTCP(
	ctx context.Context,
	dialer netio.StreamDialer,
	clientInfo netio.StreamDialerInfo,
	nameString string,
	queries []byte,
	result *resultBuilder,
) (ok bool) {
	c, err := dialer.DialStream(ctx, r.serverAddr, queries)
	if err != nil {
		r.logger.Warn("Failed to dial TCP DNS server",
			zap.String("resolver", r.name),
			zap.String("client", clientInfo.Name),
			zap.String("name", nameString),
			zap.Stringer("serverAddrPort", r.serverAddrPort),
			zap.Error(err),
		)
		return false
	}
	defer c.Close()

	stop := context.AfterFunc(ctx, func() {
		_ = c.SetReadDeadline(conn.ALongTimeAgo)
	})
	defer stop()

	lengthBuf := make([]byte, 2)

	for {
		// Read length field.
		_, err = io.ReadFull(c, lengthBuf)
		if err != nil {
			if err == io.EOF {
				return true
			}
			r.logger.Warn("Failed to read TCP DNS response length",
				zap.String("resolver", r.name),
				zap.String("client", clientInfo.Name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Error(err),
			)
			return false
		}

		msgLen := binary.BigEndian.Uint16(lengthBuf)
		if msgLen == 0 {
			r.logger.Warn("TCP DNS response length is zero",
				zap.String("resolver", r.name),
				zap.String("client", clientInfo.Name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
			)
			return false
		}

		// Read message.
		msg := make([]byte, msgLen)
		_, err = io.ReadFull(c, msg)
		if err != nil {
			r.logger.Warn("Failed to read TCP DNS response",
				zap.String("resolver", r.name),
				zap.String("client", clientInfo.Name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Error(err),
			)
			return false
		}

		header, err := result.parseMsg(msg, false)
		if err != nil {
			r.logger.Warn("Failed to parse TCP DNS response",
				zap.String("resolver", r.name),
				zap.String("client", clientInfo.Name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Error(err),
			)
			return false
		}
		if header.Truncated {
			if ce := r.logger.Check(zap.DebugLevel, "Received truncated TCP DNS response"); ce != nil {
				ce.Write(
					zap.String("resolver", r.name),
					zap.String("client", clientInfo.Name),
					zap.String("name", nameString),
					zap.Stringer("serverAddrPort", r.serverAddrPort),
					zap.Uint16("transactionID", header.ID),
				)
			}
			// TCP DNS responses exceeding 65535 bytes are truncated.
			// Use the truncated response like how Go std & the glibc resolver do.
		}
		if header.RCode != dnsmessage.RCodeSuccess {
			r.logger.Warn("Received non-success TCP DNS response",
				zap.String("resolver", r.name),
				zap.String("client", clientInfo.Name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Uint16("transactionID", header.ID),
				zap.Stringer("rcode", header.RCode),
			)
		}

		if result.isDone() {
			return true
		}
	}
}

type dnsQuery struct {
	id       uint16
	question dnsmessage.Question
	ipv6     bool
}

type resultBuilder struct {
	Result
	q4     dnsQuery
	q6     dnsQuery
	v4done bool
	v6done bool
}

type cnameAnswer struct {
	owner  string
	target string
	ttl    uint32
}

type addressAnswer struct {
	owner string
	addr  netip.Addr
	ttl   uint32
}

func canonicalDNSName(name dnsmessage.Name) string {
	return strings.ToLower(name.String())
}

func sameQuestion(got, want dnsmessage.Question) bool {
	return got.Type == want.Type && got.Class == want.Class && strings.EqualFold(got.Name.String(), want.Name.String())
}

func minExpiry(current time.Time, now time.Time, ttl uint32) time.Time {
	expiry := now.Add(time.Duration(ttl) * time.Second)
	if current.IsZero() || current.After(expiry) {
		return expiry
	}
	return current
}

func (r *resultBuilder) queryForID(id uint16) (dnsQuery, bool) {
	switch id {
	case r.q4.id:
		return r.q4, true
	case r.q6.id:
		return r.q6, true
	default:
		return dnsQuery{}, false
	}
}

func (r *resultBuilder) parseMsg(msg []byte, isUDP bool) (dnsmessage.Header, error) {
	now := time.Now()
	var parser dnsmessage.Parser

	header, err := parser.Start(msg)
	if err != nil {
		return dnsmessage.Header{}, fmt.Errorf("failed to parse query response header: %w", err)
	}
	query, ok := r.queryForID(header.ID)
	if !ok {
		return dnsmessage.Header{}, fmt.Errorf("unexpected transaction ID: %d", header.ID)
	}
	if !header.Response {
		return dnsmessage.Header{}, ErrMessageNotResponse
	}
	if !header.RecursionAvailable {
		return dnsmessage.Header{}, ErrResponseNoRecursionAvailable
	}

	question, err := parser.Question()
	if err != nil {
		return dnsmessage.Header{}, fmt.Errorf("failed to parse response question: %w", err)
	}
	if !sameQuestion(question, query.question) {
		return dnsmessage.Header{}, fmt.Errorf("response question %v does not match query %v", question, query.question)
	}
	if _, err = parser.Question(); err == nil {
		return dnsmessage.Header{}, errors.New("response contains more than one question")
	} else if err != dnsmessage.ErrSectionDone {
		return dnsmessage.Header{}, fmt.Errorf("failed to finish response questions: %w", err)
	}

	if (query.ipv6 && r.v6done) || (!query.ipv6 && r.v4done) {
		return header, nil
	}

	var responseExpiresAt time.Time
	switch header.RCode {
	case dnsmessage.RCodeSuccess, dnsmessage.RCodeNameError:
	case dnsmessage.RCodeFormatError, dnsmessage.RCodeServerFailure,
		dnsmessage.RCodeNotImplemented, dnsmessage.RCodeRefused:
		responseExpiresAt = now.Add(rcodeFailureCachingDuration)
	default:
		return dnsmessage.Header{}, fmt.Errorf("unknown RCode: %d", header.RCode)
	}

	var cnames []cnameAnswer
	var addresses []addressAnswer
	for {
		answerHeader, err := parser.AnswerHeader()
		if err != nil {
			if err == dnsmessage.ErrSectionDone {
				break
			}
			return dnsmessage.Header{}, fmt.Errorf("failed to parse answer header: %w", err)
		}
		owner := canonicalDNSName(answerHeader.Name)
		switch answerHeader.Type {
		case dnsmessage.TypeCNAME:
			if answerHeader.Class != dnsmessage.ClassINET {
				return dnsmessage.Header{}, fmt.Errorf("CNAME answer has unexpected class %v", answerHeader.Class)
			}
			resource, err := parser.CNAMEResource()
			if err != nil {
				return dnsmessage.Header{}, fmt.Errorf("failed to parse CNAME resource: %w", err)
			}
			cnames = append(cnames, cnameAnswer{owner: owner, target: canonicalDNSName(resource.CNAME), ttl: answerHeader.TTL})
		case dnsmessage.TypeA:
			if answerHeader.Class != dnsmessage.ClassINET {
				return dnsmessage.Header{}, fmt.Errorf("A answer has unexpected class %v", answerHeader.Class)
			}
			resource, err := parser.AResource()
			if err != nil {
				return dnsmessage.Header{}, fmt.Errorf("failed to parse A resource: %w", err)
			}
			if query.question.Type != dnsmessage.TypeA {
				return dnsmessage.Header{}, errors.New("AAAA response contains an A answer")
			}
			addresses = append(addresses, addressAnswer{owner: owner, addr: netip.AddrFrom4(resource.A), ttl: answerHeader.TTL})
		case dnsmessage.TypeAAAA:
			if answerHeader.Class != dnsmessage.ClassINET {
				return dnsmessage.Header{}, fmt.Errorf("AAAA answer has unexpected class %v", answerHeader.Class)
			}
			resource, err := parser.AAAAResource()
			if err != nil {
				return dnsmessage.Header{}, fmt.Errorf("failed to parse AAAA resource: %w", err)
			}
			if query.question.Type != dnsmessage.TypeAAAA {
				return dnsmessage.Header{}, errors.New("A response contains an AAAA answer")
			}
			addresses = append(addresses, addressAnswer{owner: owner, addr: netip.AddrFrom16(resource.AAAA), ttl: answerHeader.TTL})
		default:
			if err = parser.SkipAnswer(); err != nil {
				return dnsmessage.Header{}, fmt.Errorf("failed to skip answer: %w", err)
			}
		}
	}

	ownedNames := map[string]struct{}{canonicalDNSName(query.question.Name): {}}
	for changed := true; changed; {
		changed = false
		for _, cname := range cnames {
			if _, ownerIsOwned := ownedNames[cname.owner]; !ownerIsOwned {
				continue
			}
			if _, targetIsOwned := ownedNames[cname.target]; !targetIsOwned {
				ownedNames[cname.target] = struct{}{}
				changed = true
			}
		}
	}
	for _, cname := range cnames {
		if _, ok := ownedNames[cname.owner]; !ok {
			return dnsmessage.Header{}, fmt.Errorf("CNAME answer for unrelated name %q", cname.owner)
		}
		responseExpiresAt = minExpiry(responseExpiresAt, now, cname.ttl)
	}
	for _, address := range addresses {
		if _, ok := ownedNames[address.owner]; !ok {
			return dnsmessage.Header{}, fmt.Errorf("address answer for unrelated name %q", address.owner)
		}
		responseExpiresAt = minExpiry(responseExpiresAt, now, address.ttl)
	}

	if responseExpiresAt.IsZero() {
		// RFC 2308 negative caching: Parse authorities and use SOA record's TTL.
		for {
			authorityHeader, err := parser.AuthorityHeader()
			if err != nil {
				if err == dnsmessage.ErrSectionDone {
					break
				}
				return dnsmessage.Header{}, fmt.Errorf("failed to parse authority header: %w", err)
			}
			if authorityHeader.Type == dnsmessage.TypeSOA {
				responseExpiresAt = minExpiry(responseExpiresAt, now, authorityHeader.TTL)
			}
			if err := parser.SkipAuthority(); err != nil {
				return dnsmessage.Header{}, fmt.Errorf("failed to skip authority: %w", err)
			}
		}
	}

	if r.expiresAt.IsZero() || (!responseExpiresAt.IsZero() && r.expiresAt.After(responseExpiresAt)) {
		r.expiresAt = responseExpiresAt
	}
	if query.ipv6 {
		r.aaaa = r.aaaa[:0]
		for _, address := range addresses {
			r.aaaa = append(r.aaaa, address.addr)
		}
		if !header.Truncated || !isUDP {
			r.v6done = true
		}
	} else {
		r.a = r.a[:0]
		for _, address := range addresses {
			r.a = append(r.a, address.addr)
		}
		if !header.Truncated || !isUDP {
			r.v4done = true
		}
	}

	return header, nil
}

func (r *resultBuilder) isDone() bool {
	return r.v4done && r.v6done
}

// SimpleResolver defines methods that only return the resolved IP addresses.
type SimpleResolver interface {
	// LookupIP looks up [name] and returns one of the associated IP addresses.
	LookupIP(ctx context.Context, name string) (netip.Addr, error)

	// LookupIPs looks up [name] and returns all associated IP addresses.
	LookupIPs(ctx context.Context, name string) ([]netip.Addr, error)
}

// LookupIP implements [SimpleResolver.LookupIP].
func (r *Resolver) LookupIP(ctx context.Context, name string) (netip.Addr, error) {
	result, err := r.Lookup(ctx, name)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(result.aaaa) > 0 {
		return result.aaaa[0], nil
	}
	if len(result.a) > 0 {
		return result.a[0], nil
	}
	return netip.Addr{}, ErrDomainNoAssociatedIPs
}

// LookupIPs implements [SimpleResolver.LookupIPs].
func (r *Resolver) LookupIPs(ctx context.Context, name string) ([]netip.Addr, error) {
	result, err := r.Lookup(ctx, name)
	if err != nil {
		return nil, err
	}
	return slices.Concat(result.aaaa, result.a), nil
}

// SystemResolver resolves names using [net.DefaultResolver].
// It implements [SimpleResolver].
type SystemResolver struct {
	name   string
	logger *zap.Logger
}

// NewSystemResolver returns a new [SystemResolver].
func NewSystemResolver(name string, logger *zap.Logger) *SystemResolver {
	return &SystemResolver{
		name:   name,
		logger: logger,
	}
}

// LookupIP implements [SimpleResolver.LookupIP].
func (r *SystemResolver) LookupIP(ctx context.Context, name string) (netip.Addr, error) {
	ips, err := r.LookupIPs(ctx, name)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(ips) == 0 {
		return netip.Addr{}, ErrDomainNoAssociatedIPs
	}
	return ips[0], nil
}

// LookupIPs implements [SimpleResolver.LookupIPs].
func (r *SystemResolver) LookupIPs(ctx context.Context, name string) ([]netip.Addr, error) {
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", name)
	if err != nil {
		return nil, err
	}

	if ce := r.logger.Check(zap.DebugLevel, "DNS lookup got result from system resolver"); ce != nil {
		ce.Write(
			zap.String("resolver", r.name),
			zap.String("name", name),
			zap.Stringers("ips", ips),
		)
	}

	return ips, nil
}
