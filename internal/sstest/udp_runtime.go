package sstest

import (
	"context"
	"crypto/sha256"
	"errors"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	ssconn "github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/ss2022"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

const (
	udpPacketHeadroom = 512
	udpPacketCapacity = udpPacketHeadroom + 1500 + 32
)

type udpRuntime struct {
	config Config
	state  *RuntimeState

	mu             sync.Mutex
	protocol       *ss2022.UDPServer
	serverKeyHash  [sha256.Size]byte
	users          map[string]*User
	sessions       map[uint64]*udpSession
	packetCapacity int
	packetPool     sync.Pool
	metrics        udpRuntimeMetrics
}

type udpSession struct {
	id         uint64
	user       *User
	inbound    *net.UDPConn
	outbound   *net.UDPConn
	unpacker   zerocopy.ServerUnpacker
	packer     zerocopy.ServerPacker
	clientAddr atomic.Pointer[udpClientAddr]
	send       chan *udpQueuedPacket
	done       chan struct{}
	closeOnce  sync.Once
	upload     atomic.Int64
	download   atomic.Int64
}

type udpClientAddr struct {
	addr netip.AddrPort
}

type udpQueuedPacket struct {
	buf    []byte
	target ssconn.Addr
	start  int
	length int
}

type udpRuntimeMetrics struct {
	rxPackets       atomic.Uint64
	rxBytes         atomic.Uint64
	txPackets       atomic.Uint64
	txBytes         atomic.Uint64
	dropDecrypt     atomic.Uint64
	dropForbidden   atomic.Uint64
	dropSessionOpen atomic.Uint64
	dropQueueFull   atomic.Uint64
	dropResolve     atomic.Uint64
	dropTargetWrite atomic.Uint64
	dropPack        atomic.Uint64
	dropClientWrite atomic.Uint64
}

func newUDPRuntime(config Config, state *RuntimeState) *udpRuntime {
	mtu := config.UDPMTU
	if mtu < 1280 {
		mtu = 1500
	}
	if mtu > 65535 {
		mtu = 65535
	}
	r := &udpRuntime{
		config:         config,
		state:          state,
		users:          make(map[string]*User),
		sessions:       make(map[uint64]*udpSession),
		packetCapacity: udpPacketHeadroom + max(1500, mtu) + 32,
	}
	r.packetPool.New = func() any {
		return &udpQueuedPacket{buf: make([]byte, r.packetCapacity)}
	}
	return r
}

func (r *udpRuntime) configure(node NodeInfo, users []User) error {
	userLookup := make(ss2022.UserLookupMap, len(users))
	usersByName := make(map[string]*User, len(users))
	for i := range users {
		name := strconv.Itoa(users[i].ID)
		cipherConfig, err := ss2022.NewServerUserCipherConfig(name, users[i].UserKey, true)
		if err != nil {
			return err
		}
		userLookup[ss2022.PSKHash(users[i].UserKey)] = cipherConfig
		usersByName[name] = &users[i]
	}

	keyHash := sha256.Sum256(node.ServerKey)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.protocol == nil || r.serverKeyHash != keyHash {
		identityConfig, err := ss2022.NewServerIdentityCipherConfig(node.ServerKey, true)
		if err != nil {
			return err
		}
		r.closeAllLocked()
		r.protocol = ss2022.NewUDPServer(
			ss2022.DefaultSlidingWindowFilterSize,
			ss2022.UserCipherConfig{},
			identityConfig,
			ss2022.NoPadding,
		)
		r.serverKeyHash = keyHash
	}
	r.protocol.ReplaceUserLookupMap(userLookup)
	r.users = usersByName
	return nil
}

func (r *udpRuntime) serve(inbound *net.UDPConn) {
	for {
		queued := r.getPacket()
		recvBuf := queued.buf[udpPacketHeadroom : len(queued.buf)-32]
		n, clientAddr, err := inbound.ReadFromUDPAddrPort(recvBuf)
		if err != nil {
			r.putPacket(queued)
			return
		}
		r.metrics.rxPackets.Add(1)
		r.metrics.rxBytes.Add(uint64(n))
		if !r.dispatch(inbound, queued, clientAddr, n) {
			r.putPacket(queued)
		}
	}
}

func (r *udpRuntime) dispatch(inbound *net.UDPConn, queued *udpQueuedPacket, clientAddr netip.AddrPort, packetLen int) bool {
	packet := queued.buf[udpPacketHeadroom : udpPacketHeadroom+packetLen]

	r.mu.Lock()
	protocol := r.protocol
	if protocol == nil {
		r.mu.Unlock()
		r.metrics.dropDecrypt.Add(1)
		return false
	}
	clientSessionID, err := protocol.SessionInfo(packet)
	if err != nil {
		r.mu.Unlock()
		r.metrics.dropDecrypt.Add(1)
		return false
	}

	session := r.sessions[clientSessionID]
	newSession := session == nil
	if newSession {
		unpacker, username, err := protocol.NewUnpacker(packet, clientSessionID)
		if err != nil {
			r.mu.Unlock()
			r.metrics.dropDecrypt.Add(1)
			return false
		}
		user := r.users[username]
		if user == nil {
			r.mu.Unlock()
			r.metrics.dropDecrypt.Add(1)
			return false
		}
		session, err = r.newSessionLocked(clientSessionID, user, inbound, unpacker)
		if err != nil {
			r.mu.Unlock()
			r.metrics.dropSessionOpen.Add(1)
			log.Printf("debug: udp session open failed: %v", err)
			return false
		}
	}

	queued.target, queued.start, queued.length, err = session.unpacker.UnpackInPlace(
		queued.buf,
		clientAddr,
		udpPacketHeadroom,
		packetLen,
	)
	if err != nil {
		if newSession {
			delete(r.sessions, session.id)
			r.closeSessionLocked(session)
		}
		r.mu.Unlock()
		r.metrics.dropDecrypt.Add(1)
		return false
	}

	clientIP := clientAddr.Addr().Unmap().String()
	targetHost := queued.target.Host()
	targetPort := int(queued.target.Port())
	if isDisconnectIP(session.user, clientIP) ||
		isForbiddenPort(session.user, targetPort) ||
		isForbiddenHost(session.user, targetHost) {
		if newSession {
			delete(r.sessions, session.id)
			r.closeSessionLocked(session)
		}
		r.mu.Unlock()
		r.metrics.dropForbidden.Add(1)
		return false
	}

	previousAddr := session.clientAddr.Load()
	session.clientAddr.Store(&udpClientAddr{addr: clientAddr})
	enqueued := false
	select {
	case <-session.done:
		enqueued = false
	case session.send <- queued:
		enqueued = true
	default:
		r.metrics.dropQueueFull.Add(1)
	}
	r.mu.Unlock()

	if newSession || previousAddr == nil || previousAddr.addr != clientAddr {
		r.state.AddAliveIP(session.user.ID, clientIP)
	}
	return enqueued
}

func (r *udpRuntime) newSessionLocked(
	id uint64,
	user *User,
	inbound *net.UDPConn,
	unpacker zerocopy.ServerUnpacker,
) (*udpSession, error) {
	outbound, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	tuneUDP(outbound, r.config)
	packer, err := unpacker.NewPacker()
	if err != nil {
		_ = outbound.Close()
		return nil, err
	}
	queueSize := r.config.UDPQueueSize
	if queueSize <= 0 {
		queueSize = 4096
	}
	session := &udpSession{
		id:       id,
		user:     user,
		inbound:  inbound,
		outbound: outbound,
		unpacker: unpacker,
		packer:   packer,
		send:     make(chan *udpQueuedPacket, queueSize),
		done:     make(chan struct{}),
	}
	session.clientAddr.Store(&udpClientAddr{})
	r.sessions[id] = session
	_ = outbound.SetReadDeadline(time.Now().Add(r.idleTimeout()))
	go r.relayUplink(session)
	go r.relayDownlink(session)
	return session, nil
}

func (r *udpRuntime) relayUplink(session *udpSession) {
	resolved := make(map[string]netip.AddrPort)
	defer func() {
		for {
			select {
			case queued := <-session.send:
				r.putPacket(queued)
			default:
				return
			}
		}
	}()

	for {
		select {
		case <-session.done:
			return
		case queued := <-session.send:
			targetKey := queued.target.String()
			targetAddr, ok := resolved[targetKey]
			if !ok {
				ctx, cancel := context.WithTimeout(context.Background(), time.Duration(r.config.TCPConnectTimeout)*time.Second)
				var err error
				targetAddr, err = queued.target.ResolveIPPort(ctx, "ip")
				cancel()
				if err != nil {
					r.metrics.dropResolve.Add(1)
					r.putPacket(queued)
					continue
				}
				resolved[targetKey] = targetAddr
			}
			_, err := session.outbound.WriteToUDPAddrPort(
				queued.buf[queued.start:queued.start+queued.length],
				targetAddr,
			)
			if err != nil {
				if !isExpectedCloseError(err) {
					r.metrics.dropTargetWrite.Add(1)
				}
				r.putPacket(queued)
				continue
			}
			session.upload.Add(int64(queued.length))
			_ = session.outbound.SetReadDeadline(time.Now().Add(r.idleTimeout()))
			r.putPacket(queued)
		}
	}
}

func (r *udpRuntime) relayDownlink(session *udpSession) {
	defer r.closeSession(session)
	buf := make([]byte, r.packetCapacity)
	recvBuf := buf[udpPacketHeadroom : len(buf)-32]

	for {
		n, sourceAddr, err := session.outbound.ReadFromUDPAddrPort(recvBuf)
		if err != nil {
			if !errors.Is(err, os.ErrDeadlineExceeded) && !isExpectedCloseError(err) {
				log.Printf("debug: udp target read failed: %v", err)
			}
			return
		}
		client := session.clientAddr.Load()
		if client == nil || !client.addr.IsValid() {
			continue
		}
		maxPacketSize := zerocopy.MaxPacketSizeForAddr(r.udpMTU(), client.addr.Addr())
		packetStart, packetLen, err := session.packer.PackInPlace(
			buf,
			sourceAddr,
			udpPacketHeadroom,
			n,
			maxPacketSize,
		)
		if err != nil {
			r.metrics.dropPack.Add(1)
			continue
		}
		if _, err := session.inbound.WriteToUDPAddrPort(
			buf[packetStart:packetStart+packetLen],
			client.addr,
		); err != nil {
			if !isExpectedCloseError(err) {
				r.metrics.dropClientWrite.Add(1)
			}
			continue
		}
		r.metrics.txPackets.Add(1)
		r.metrics.txBytes.Add(uint64(n))
		session.download.Add(int64(n))
	}
}

func (r *udpRuntime) closeSession(session *udpSession) {
	r.mu.Lock()
	if r.sessions[session.id] == session {
		delete(r.sessions, session.id)
	}
	r.closeSessionLocked(session)
	r.mu.Unlock()
	r.flushSessionTraffic(session)
}

func (r *udpRuntime) closeSessionLocked(session *udpSession) {
	session.closeOnce.Do(func() {
		close(session.done)
		_ = session.outbound.Close()
	})
}

func (r *udpRuntime) closeAll() {
	r.mu.Lock()
	r.closeAllLocked()
	r.mu.Unlock()
}

func (r *udpRuntime) closeAllLocked() {
	for id, session := range r.sessions {
		r.closeSessionLocked(session)
		delete(r.sessions, id)
		r.flushSessionTraffic(session)
	}
}

func (r *udpRuntime) flushTraffic(inbound *net.UDPConn, current func() *net.UDPConn) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if current() != inbound {
			return
		}
		r.mu.Lock()
		sessions := make([]*udpSession, 0, len(r.sessions))
		for _, session := range r.sessions {
			sessions = append(sessions, session)
		}
		r.mu.Unlock()
		for _, session := range sessions {
			r.flushSessionTraffic(session)
		}
	}
}

func (r *udpRuntime) flushSessionTraffic(session *udpSession) {
	upload := session.upload.Swap(0)
	download := session.download.Swap(0)
	r.state.AddTraffic(session.user.ID, upload, download)
}

func (r *udpRuntime) reportMetrics(inbound *net.UDPConn, current func() *net.UDPConn) {
	interval := time.Duration(r.config.UDPMetricsSeconds) * time.Second
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		if current() != inbound {
			return
		}
		r.mu.Lock()
		sessionCount := len(r.sessions)
		r.mu.Unlock()
		log.Printf(
			"udp metrics: rx_packets=%d rx_bytes=%d tx_packets=%d tx_bytes=%d drop_decrypt=%d drop_forbidden=%d drop_session_open=%d drop_queue_full=%d drop_resolve=%d drop_target_write=%d drop_pack=%d drop_client_write=%d sessions=%d",
			r.metrics.rxPackets.Load(),
			r.metrics.rxBytes.Load(),
			r.metrics.txPackets.Load(),
			r.metrics.txBytes.Load(),
			r.metrics.dropDecrypt.Load(),
			r.metrics.dropForbidden.Load(),
			r.metrics.dropSessionOpen.Load(),
			r.metrics.dropQueueFull.Load(),
			r.metrics.dropResolve.Load(),
			r.metrics.dropTargetWrite.Load(),
			r.metrics.dropPack.Load(),
			r.metrics.dropClientWrite.Load(),
			sessionCount,
		)
	}
}

func (r *udpRuntime) getPacket() *udpQueuedPacket {
	return r.packetPool.Get().(*udpQueuedPacket)
}

func (r *udpRuntime) putPacket(queued *udpQueuedPacket) {
	queued.target = ssconn.Addr{}
	queued.start = 0
	queued.length = 0
	r.packetPool.Put(queued)
}

func (r *udpRuntime) idleTimeout() time.Duration {
	seconds := r.config.UDPIdleTimeout
	if seconds < 60 {
		seconds = 60
	}
	return time.Duration(seconds) * time.Second
}

func (r *udpRuntime) udpMTU() int {
	if r.config.UDPMTU < 1280 {
		return 1500
	}
	if r.config.UDPMTU > 65535 {
		return 65535
	}
	return r.config.UDPMTU
}
