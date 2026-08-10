package service

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/database64128/shadowsocks-go"
	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/router"
	"github.com/database64128/shadowsocks-go/stats"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
)

// sessionQueuedPacket is the structure used by send channels to queue packets for sending.
type sessionQueuedPacket struct {
	buf            []byte
	start          int
	length         int
	targetAddr     conn.Addr
	clientAddrPort netip.AddrPort
}

// sessionClientAddrInfo stores a session's client address information.
type sessionClientAddrInfo struct {
	addrPort netip.AddrPort
	pktinfo  []byte
}

// session keeps track of a UDP session.
type session struct {
	// state synchronizes session initialization and shutdown.
	//
	//  - Swap the natConn in to signal initialization completion.
	//  - Swap the serverConn in to signal shutdown.
	//
	// Callers must check the swapped-out value to determine the next action.
	//
	//  - During initialization, if the swapped-out value is non-nil,
	//    initialization must not proceed.
	//  - During shutdown, if the swapped-out value is nil, preceed to the next entry.
	state               atomic.Pointer[net.UDPConn]
	clientAddrInfo      atomic.Pointer[sessionClientAddrInfo]
	clientAddrPortCache netip.AddrPort
	clientPktinfoCache  []byte
	natConnSendCh       chan<- *sessionQueuedPacket
	serverConn          *net.UDPConn
	serverConnUnpacker  zerocopy.ServerUnpacker
	username            string
	runtimeSession      RuntimeSession
	logger              *zap.Logger
}

// sessionUplinkGeneric is used for passing information about relay uplink to the relay goroutine.
type sessionUplinkGeneric struct {
	csid           uint64
	clientName     string
	natConn        *net.UDPConn
	natConnSendCh  <-chan *sessionQueuedPacket
	natConnPacker  zerocopy.ClientPacker
	natTimeout     time.Duration
	username       string
	runtimeSession RuntimeSession
	logger         *zap.Logger
}

// sessionDownlinkGeneric is used for passing information about relay downlink to the relay goroutine.
type sessionDownlinkGeneric struct {
	ctx                context.Context
	csid               uint64
	clientName         string
	clientAddrInfop    *sessionClientAddrInfo
	clientAddrInfo     *atomic.Pointer[sessionClientAddrInfo]
	natConn            *net.UDPConn
	natConnRecvBufSize int
	natConnUnpacker    zerocopy.ClientUnpacker
	serverConn         *net.UDPConn
	serverConnPacker   zerocopy.ServerPacker
	username           string
	runtimeSession     RuntimeSession
	logger             *zap.Logger
}

// UDPSessionRelay is a session-based UDP relay service.
//
// Incoming UDP packets are dispatched to NAT sessions based on the client session ID.
type UDPSessionRelay struct {
	serverName             string
	serverIndex            int
	mtu                    int
	packetBufFrontHeadroom int
	packetBufRecvSize      int
	listeners              []udpRelayServerConn
	server                 zerocopy.UDPSessionServer
	collector              stats.Collector
	observer               RuntimeObserver
	sessionFactory         RuntimeSessionFactory
	router                 *router.Router
	logger                 *zap.Logger
	queuedPacketPool       sync.Pool
	mu                     sync.Mutex
	wg                     sync.WaitGroup
	mwg                    sync.WaitGroup
	table                  map[uint64]*session
	sessionsByUser         map[string]int
	lastLimitedUser        string
	rxPackets              atomic.Uint64
	rxBytes                atomic.Uint64
	dropDecrypt            atomic.Uint64
	dropForbidden          atomic.Uint64
	dropPolicyResolution   atomic.Uint64
	dropQueueFull          atomic.Uint64
	dropSessionLimit       atomic.Uint64
	dropUserSessionLimit   atomic.Uint64
	peakSessions           atomic.Uint64
}

func NewUDPSessionRelay(
	serverName string,
	serverIndex, mtu, packetBufFrontHeadroom, packetBufRecvSize, packetBufSize int,
	listeners []udpRelayServerConn,
	server zerocopy.UDPSessionServer,
	collector stats.Collector,
	observer RuntimeObserver,
	router *router.Router,
	logger *zap.Logger,
) *UDPSessionRelay {
	return &UDPSessionRelay{
		serverName:             serverName,
		serverIndex:            serverIndex,
		mtu:                    mtu,
		packetBufFrontHeadroom: packetBufFrontHeadroom,
		packetBufRecvSize:      packetBufRecvSize,
		listeners:              listeners,
		server:                 server,
		collector:              collector,
		observer:               observer,
		sessionFactory:         runtimeSessionFactory(observer),
		router:                 router,
		logger:                 logger,
		queuedPacketPool: sync.Pool{
			New: func() any {
				return &sessionQueuedPacket{
					buf: make([]byte, packetBufSize),
				}
			},
		},
		table:          make(map[uint64]*session),
		sessionsByUser: make(map[string]int),
	}
}

// reserveSession reserves capacity for a new session. The caller must hold s.mu.
func (s *UDPSessionRelay) reserveSession(username string, lnc *udpRelayServerConn) bool {
	if lnc.maxSessions > 0 && len(s.table) >= lnc.maxSessions {
		s.dropSessionLimit.Add(1)
		return false
	}
	if lnc.maxSessionsPerUser > 0 && s.sessionsByUser[username] >= lnc.maxSessionsPerUser {
		s.dropUserSessionLimit.Add(1)
		s.lastLimitedUser = username
		return false
	}
	s.sessionsByUser[username]++
	return true
}

// releaseSession releases a session reservation. The caller must hold s.mu.
func (s *UDPSessionRelay) releaseSession(username string) {
	remaining := s.sessionsByUser[username] - 1
	if remaining <= 0 {
		delete(s.sessionsByUser, username)
		return
	}
	s.sessionsByUser[username] = remaining
}

func (s *UDPSessionRelay) updatePeakSessions(active int) {
	value := uint64(active)
	for peak := s.peakSessions.Load(); value > peak; peak = s.peakSessions.Load() {
		if s.peakSessions.CompareAndSwap(peak, value) {
			return
		}
	}
}

var _ shadowsocks.Service = (*UDPSessionRelay)(nil)

// ZapField implements [shadowsocks.Service.ZapField].
func (s *UDPSessionRelay) ZapField() zap.Field {
	return zap.String("serverUDPSessionRelay", s.serverName)
}

// Start implements [shadowsocks.Service.Start].
func (s *UDPSessionRelay) Start(ctx context.Context) error {
	for i := range s.listeners {
		if err := s.start(ctx, i, &s.listeners[i]); err != nil {
			return err
		}
	}
	go s.logMetrics(ctx)
	return nil
}

func (s *UDPSessionRelay) logMetrics(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	var lastSessionLimitDrops uint64
	var lastUserSessionLimitDrops uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			activeSessions := len(s.table)
			lastLimitedUser := s.lastLimitedUser
			var busiestUser string
			var busiestUserSessions int
			for username, sessions := range s.sessionsByUser {
				if sessions > busiestUserSessions {
					busiestUser = username
					busiestUserSessions = sessions
				}
			}
			s.mu.Unlock()
			sessionLimitDrops := s.dropSessionLimit.Load()
			userSessionLimitDrops := s.dropUserSessionLimit.Load()
			var maxSessions int
			var maxSessionsPerUser int
			if len(s.listeners) > 0 {
				maxSessions = s.listeners[0].maxSessions
				maxSessionsPerUser = s.listeners[0].maxSessionsPerUser
			}
			s.logger.Info("UDP relay metrics",
				zap.Uint64("rxPackets", s.rxPackets.Load()),
				zap.Uint64("rxBytes", s.rxBytes.Load()),
				zap.Uint64("dropDecrypt", s.dropDecrypt.Load()),
				zap.Uint64("dropForbidden", s.dropForbidden.Load()),
				zap.Uint64("dropPolicyResolution", s.dropPolicyResolution.Load()),
				zap.Uint64("dropQueueFull", s.dropQueueFull.Load()),
				zap.Uint64("dropSessionLimit", sessionLimitDrops),
				zap.Uint64("dropUserSessionLimit", userSessionLimitDrops),
				zap.Int("activeSessions", activeSessions),
				zap.Uint64("peakSessions", s.peakSessions.Load()),
				zap.String("busiestUser", busiestUser),
				zap.Int("busiestUserSessions", busiestUserSessions),
				zap.Int("maxSessions", maxSessions),
				zap.Int("maxSessionsPerUser", maxSessionsPerUser),
				zap.String("lastLimitedUser", lastLimitedUser),
			)
			if delta := sessionLimitDrops - lastSessionLimitDrops; delta > 0 {
				s.logger.Warn("UDP sessions rejected by global limit",
					zap.Uint64("rejectedSinceLastReport", delta),
					zap.Uint64("rejectedTotal", sessionLimitDrops),
					zap.Int("activeSessions", activeSessions),
					zap.Int("maxSessions", maxSessions),
				)
			}
			if delta := userSessionLimitDrops - lastUserSessionLimitDrops; delta > 0 {
				s.logger.Warn("UDP sessions rejected by per-user limit",
					zap.Uint64("rejectedSinceLastReport", delta),
					zap.Uint64("rejectedTotal", userSessionLimitDrops),
					zap.String("username", lastLimitedUser),
					zap.Int("busiestUserSessions", busiestUserSessions),
					zap.Int("maxSessionsPerUser", maxSessionsPerUser),
				)
			}
			lastSessionLimitDrops = sessionLimitDrops
			lastUserSessionLimitDrops = userSessionLimitDrops
		}
	}
}

func (s *UDPSessionRelay) startGeneric(ctx context.Context, index int, lnc *udpRelayServerConn) (err error) {
	lnc.serverConn, _, err = lnc.listenConfig.ListenUDP(ctx, lnc.network, lnc.address)
	if err != nil {
		return
	}
	lnc.address = lnc.serverConn.LocalAddr().String()
	lnc.logger = s.logger.With(
		zap.String("server", s.serverName),
		zap.Int("listener", index),
		zap.String("listenAddress", lnc.address),
	)

	s.mwg.Go(func() {
		s.recvFromServerConnGeneric(ctx, lnc)
	})

	lnc.logger.Info("Started UDP session relay service listener")
	return
}

func (s *UDPSessionRelay) recvFromServerConnGeneric(ctx context.Context, lnc *udpRelayServerConn) {
	cmsgBuf := make([]byte, conn.SocketControlMessageBufferSize)

	var (
		n                    int
		cmsgn                int
		flags                int
		err                  error
		packetsReceived      uint64
		payloadBytesReceived uint64
	)
	var readFailures udpReadErrorBackoff

	for {
		queuedPacket := s.getQueuedPacket()
		recvBuf := queuedPacket.buf[s.packetBufFrontHeadroom : s.packetBufFrontHeadroom+s.packetBufRecvSize]

		n, cmsgn, flags, queuedPacket.clientAddrPort, err = lnc.serverConn.ReadMsgUDPAddrPort(recvBuf, cmsgBuf)
		if err != nil {
			retry := readFailures.shouldRetry(ctx, err, func(err error) {
				lnc.logger.Warn("Failed to read packet from serverConn",
					zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
					zap.Int("packetLength", n),
					zap.Error(err),
				)
			})
			s.putQueuedPacket(queuedPacket)
			if !retry {
				break
			}
			continue
		}
		readFailures.reset()
		err = conn.ParseFlagsForError(flags)
		if err != nil {
			lnc.logger.Warn("Failed to read packet from serverConn",
				zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
				zap.Int("packetLength", n),
				zap.Error(err),
			)

			s.putQueuedPacket(queuedPacket)
			continue
		}
		s.rxPackets.Add(1)
		s.rxBytes.Add(uint64(n))

		packet := recvBuf[:n]

		csid, err := s.server.SessionInfo(packet)
		if err != nil {
			s.dropDecrypt.Add(1)
			lnc.logger.Warn("Failed to extract session info from packet",
				zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
				zap.Int("packetLength", n),
				zap.Error(err),
			)

			s.putQueuedPacket(queuedPacket)
			continue
		}

		s.mu.Lock()

		entry, ok := s.table[csid]
		if !ok {
			entry = &session{
				serverConn: lnc.serverConn,
				logger:     lnc.logger,
			}

			entry.serverConnUnpacker, entry.username, err = s.server.NewUnpacker(packet, csid)
			if err != nil {
				s.dropDecrypt.Add(1)
				lnc.logger.Warn("Failed to create unpacker for client session",
					zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
					zap.Uint64("clientSessionID", csid),
					zap.Int("packetLength", n),
					zap.Error(err),
				)

				s.putQueuedPacket(queuedPacket)
				s.mu.Unlock()
				continue
			}
		}

		queuedPacket.targetAddr, queuedPacket.start, queuedPacket.length, err = entry.serverConnUnpacker.UnpackInPlace(queuedPacket.buf, queuedPacket.clientAddrPort, s.packetBufFrontHeadroom, n)
		if err != nil {
			s.dropDecrypt.Add(1)
			lnc.logger.Warn("Failed to unpack packet",
				zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
				zap.String("username", entry.username),
				zap.Uint64("clientSessionID", csid),
				zap.Int("packetLength", n),
				zap.Error(err),
			)

			s.putQueuedPacket(queuedPacket)
			s.mu.Unlock()
			continue
		}
		if ok && s.sessionFactory != nil && (entry.runtimeSession == nil || !entry.runtimeSession.Active()) {
			s.dropForbidden.Add(1)
			s.putQueuedPacket(queuedPacket)
			s.mu.Unlock()
			continue
		}
		if s.sessionFactory == nil && s.observer != nil && !s.observer.Accept("udp", entry.username, queuedPacket.clientAddrPort, queuedPacket.targetAddr) {
			s.dropForbidden.Add(1)
			s.putQueuedPacket(queuedPacket)
			s.mu.Unlock()
			continue
		}

		packetsReceived++
		payloadBytesReceived += uint64(queuedPacket.length)

		var clientAddrInfop *sessionClientAddrInfo
		cmsg := cmsgBuf[:cmsgn]

		updateClientAddrPort := entry.clientAddrPortCache != queuedPacket.clientAddrPort
		updateClientPktinfo := !bytes.Equal(entry.clientPktinfoCache, cmsg)

		if updateClientAddrPort {
			entry.clientAddrPortCache = queuedPacket.clientAddrPort
			if entry.runtimeSession != nil {
				entry.runtimeSession.Observe(queuedPacket.clientAddrPort)
			} else if s.sessionFactory == nil && s.observer != nil {
				s.observer.Observe("udp", entry.username, queuedPacket.clientAddrPort)
			}
		}

		if updateClientPktinfo {
			entry.clientPktinfoCache = make([]byte, len(cmsg))
			copy(entry.clientPktinfoCache, cmsg)
		}

		if updateClientAddrPort || updateClientPktinfo {
			m, err := conn.ParseSocketControlMessage(cmsg)
			if err != nil {
				lnc.logger.Error("Failed to parse pktinfo control message from serverConn",
					zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
					zap.String("username", entry.username),
					zap.Uint64("clientSessionID", csid),
					zap.Stringer("targetAddress", &queuedPacket.targetAddr),
					zap.Error(err),
				)

				s.putQueuedPacket(queuedPacket)
				s.mu.Unlock()
				continue
			}

			clientAddrInfop = &sessionClientAddrInfo{entry.clientAddrPortCache, entry.clientPktinfoCache}
			entry.clientAddrInfo.Store(clientAddrInfop)

			if ce := lnc.logger.Check(zap.DebugLevel, "Updated client address info"); ce != nil {
				ce.Write(
					zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
					zap.String("username", entry.username),
					zap.Uint64("clientSessionID", csid),
					zap.Stringer("targetAddress", &queuedPacket.targetAddr),
					zap.Stringer("clientPktinfoAddr", m.PktinfoAddr),
					zap.Uint32("clientPktinfoIfindex", m.PktinfoIfindex),
				)
			}
		}

		if !ok {
			if s.sessionFactory != nil {
				var accepted bool
				entry.runtimeSession, accepted = s.sessionFactory.OpenRuntimeSession(
					"udp", entry.username, queuedPacket.clientAddrPort, queuedPacket.targetAddr,
				)
				if !accepted {
					s.dropForbidden.Add(1)
					s.putQueuedPacket(queuedPacket)
					s.mu.Unlock()
					continue
				}
				entry.runtimeSession.Observe(queuedPacket.clientAddrPort)
			}
			if !s.reserveSession(entry.username, lnc) {
				if entry.runtimeSession != nil {
					entry.runtimeSession.Close()
				}
				s.putQueuedPacket(queuedPacket)
				s.mu.Unlock()
				continue
			}
			natConnSendCh := make(chan *sessionQueuedPacket, lnc.sendChannelCapacity)
			entry.natConnSendCh = natConnSendCh
			s.table[csid] = entry
			s.updatePeakSessions(len(s.table))

			s.wg.Go(func() {
				var sendChClean bool

				defer func() {
					if entry.runtimeSession != nil {
						entry.runtimeSession.Close()
					}
					s.mu.Lock()
					close(natConnSendCh)
					delete(s.table, csid)
					s.releaseSession(entry.username)
					s.mu.Unlock()

					if !sendChClean {
						for queuedPacket := range natConnSendCh {
							s.putQueuedPacket(queuedPacket)
						}
					}
				}()
				relayCtx := ctx
				if entry.runtimeSession != nil {
					var cancel context.CancelFunc
					relayCtx, cancel = context.WithCancel(ctx)
					stopRuntimeCancellation := context.AfterFunc(entry.runtimeSession.Context(), cancel)
					defer stopRuntimeCancellation()
					defer cancel()
				}

				c, err := s.router.GetUDPClient(relayCtx, router.RequestInfo{
					ServerIndex:    s.serverIndex,
					Username:       entry.username,
					SourceAddrPort: queuedPacket.clientAddrPort,
					TargetAddr:     queuedPacket.targetAddr,
				})
				if err != nil {
					lnc.logger.Warn("Failed to get UDP client for new NAT session",
						zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
						zap.String("username", entry.username),
						zap.Uint64("clientSessionID", csid),
						zap.Stringer("targetAddress", &queuedPacket.targetAddr),
						zap.Error(err),
					)
					return
				}

				clientInfo, clientSession, err := c.NewSession(relayCtx)
				if err != nil {
					lnc.logger.Warn("Failed to create new UDP client session",
						zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
						zap.String("username", entry.username),
						zap.Uint64("clientSessionID", csid),
						zap.Stringer("targetAddress", &queuedPacket.targetAddr),
						zap.String("client", clientInfo.Name),
						zap.Error(err),
					)
					return
				}

				natConn, _, err := clientInfo.ListenConfig.ListenUDP(relayCtx, "udp", "")
				if err != nil {
					lnc.logger.Warn("Failed to create UDP socket for new NAT session",
						zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
						zap.String("username", entry.username),
						zap.Uint64("clientSessionID", csid),
						zap.Stringer("targetAddress", &queuedPacket.targetAddr),
						zap.String("client", clientInfo.Name),
						zap.Error(err),
					)
					clientSession.Close()
					return
				}

				err = natConn.SetReadDeadline(time.Now().Add(lnc.natTimeout))
				if err != nil {
					lnc.logger.Error("Failed to set read deadline on natConn",
						zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
						zap.String("username", entry.username),
						zap.Uint64("clientSessionID", csid),
						zap.Stringer("targetAddress", &queuedPacket.targetAddr),
						zap.String("client", clientInfo.Name),
						zap.Duration("natTimeout", lnc.natTimeout),
						zap.Error(err),
					)
					natConn.Close()
					clientSession.Close()
					return
				}

				serverConnPacker, err := entry.serverConnUnpacker.NewPacker()
				if err != nil {
					lnc.logger.Warn("Failed to create packer for client session",
						zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
						zap.String("username", entry.username),
						zap.Uint64("clientSessionID", csid),
						zap.Stringer("targetAddress", &queuedPacket.targetAddr),
						zap.Error(err),
					)
					natConn.Close()
					clientSession.Close()
					return
				}

				oldState := entry.state.Swap(natConn)
				if oldState != nil {
					natConn.Close()
					clientSession.Close()
					return
				}

				// No more early returns!
				sendChClean = true
				if entry.runtimeSession != nil {
					stopRuntimeClose := closeConnectionsOnRuntimeEnd(entry.runtimeSession, natConn)
					defer stopRuntimeClose()
				}

				lnc.logger.Debug("UDP session relay started",
					zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
					zap.String("username", entry.username),
					zap.Uint64("clientSessionID", csid),
					zap.Stringer("targetAddress", &queuedPacket.targetAddr),
					zap.String("client", clientInfo.Name),
				)

				s.wg.Go(func() {
					s.relayServerConnToNatConnGeneric(relayCtx, sessionUplinkGeneric{
						csid:           csid,
						clientName:     clientInfo.Name,
						natConn:        natConn,
						natConnSendCh:  natConnSendCh,
						natConnPacker:  clientSession.Packer,
						natTimeout:     lnc.natTimeout,
						username:       entry.username,
						runtimeSession: entry.runtimeSession,
						logger:         lnc.logger,
					})
					natConn.Close()
					clientSession.Close()
				})

				s.relayNatConnToServerConnGeneric(sessionDownlinkGeneric{
					ctx:                relayCtx,
					csid:               csid,
					clientName:         clientInfo.Name,
					clientAddrInfop:    clientAddrInfop,
					clientAddrInfo:     &entry.clientAddrInfo,
					natConn:            natConn,
					natConnRecvBufSize: clientSession.MaxPacketSize,
					natConnUnpacker:    clientSession.Unpacker,
					serverConn:         lnc.serverConn,
					serverConnPacker:   serverConnPacker,
					username:           entry.username,
					runtimeSession:     entry.runtimeSession,
					logger:             lnc.logger,
				})
			})

			if ce := lnc.logger.Check(zap.DebugLevel, "New UDP session"); ce != nil {
				ce.Write(
					zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
					zap.String("username", entry.username),
					zap.Uint64("clientSessionID", csid),
					zap.Stringer("targetAddress", &queuedPacket.targetAddr),
				)
			}
		}

		select {
		case entry.natConnSendCh <- queuedPacket:
		default:
			s.dropQueueFull.Add(1)
			if ce := lnc.logger.Check(zap.DebugLevel, "Dropping packet due to full send channel"); ce != nil {
				ce.Write(
					zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
					zap.String("username", entry.username),
					zap.Uint64("clientSessionID", csid),
					zap.Stringer("targetAddress", &queuedPacket.targetAddr),
				)
			}

			s.putQueuedPacket(queuedPacket)
		}

		s.mu.Unlock()
	}

	lnc.logger.Info("Finished receiving from serverConn",
		zap.Uint64("packetsReceived", packetsReceived),
		zap.Uint64("payloadBytesReceived", payloadBytesReceived),
	)
}

func (s *UDPSessionRelay) relayServerConnToNatConnGeneric(ctx context.Context, uplink sessionUplinkGeneric) {
	var (
		destAddrPort     netip.AddrPort
		packetStart      int
		packetLength     int
		err              error
		packetsSent      uint64
		payloadBytesSent uint64
	)

	for queuedPacket := range uplink.natConnSendCh {
		destAddrPort, packetStart, packetLength, err = uplink.natConnPacker.PackInPlace(ctx, queuedPacket.buf, queuedPacket.targetAddr, queuedPacket.start, queuedPacket.length)
		if err != nil {
			if recordOutboundPolicyDrop(err, &s.dropForbidden, &s.dropPolicyResolution) {
				s.putQueuedPacket(queuedPacket)
				continue
			}
			uplink.logger.Warn("Failed to pack packet",
				zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
				zap.String("username", uplink.username),
				zap.Uint64("clientSessionID", uplink.csid),
				zap.Stringer("targetAddress", &queuedPacket.targetAddr),
				zap.String("client", uplink.clientName),
				zap.Int("payloadLength", queuedPacket.length),
				zap.Error(err),
			)

			s.putQueuedPacket(queuedPacket)
			continue
		}
		reservation, accepted := reserveFullRuntimeTraffic(
			uplink.runtimeSession, RuntimeTrafficUplink, 1, uint64(queuedPacket.length),
		)
		if !accepted {
			s.dropForbidden.Add(1)
			s.putQueuedPacket(queuedPacket)
			continue
		}

		func() {
			if reservation != nil {
				defer reservation.Refund()
			}
			written, writeErr := uplink.natConn.WriteToUDPAddrPort(queuedPacket.buf[packetStart:packetStart+packetLength], destAddrPort)
			err = writeErr
			if err != nil {
				uplink.logger.Warn("Failed to write packet to natConn",
					zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
					zap.String("username", uplink.username),
					zap.Uint64("clientSessionID", uplink.csid),
					zap.Stringer("targetAddress", &queuedPacket.targetAddr),
					zap.String("client", uplink.clientName),
					zap.Stringer("writeDestAddress", destAddrPort),
					zap.Int("packetLength", packetLength),
					zap.Error(err),
				)
			} else if written != packetLength {
				err = io.ErrShortWrite
				uplink.logger.Warn("Partial UDP packet write to natConn was discarded",
					zap.String("username", uplink.username),
					zap.Uint64("clientSessionID", uplink.csid),
					zap.Int("written", written),
					zap.Int("packetLength", packetLength),
				)
			} else if reservation != nil {
				reservation.Commit(uint64(queuedPacket.length))
			} else {
				s.collector.CollectUDPSessionUplink(uplink.username, 1, uint64(queuedPacket.length))
			}
		}()

		err = uplink.natConn.SetReadDeadline(time.Now().Add(uplink.natTimeout))
		if err != nil {
			uplink.logger.Error("Failed to set read deadline on natConn",
				zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
				zap.String("username", uplink.username),
				zap.Uint64("clientSessionID", uplink.csid),
				zap.String("client", uplink.clientName),
				zap.Duration("natTimeout", uplink.natTimeout),
				zap.Error(err),
			)
		}

		s.putQueuedPacket(queuedPacket)
		packetsSent++
		payloadBytesSent += uint64(queuedPacket.length)
	}

	uplink.logger.Debug("Finished relay serverConn -> natConn",
		zap.String("username", uplink.username),
		zap.Uint64("clientSessionID", uplink.csid),
		zap.String("client", uplink.clientName),
		zap.Stringer("lastWriteDestAddress", destAddrPort),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("payloadBytesSent", payloadBytesSent),
	)

}

func (s *UDPSessionRelay) relayNatConnToServerConnGeneric(downlink sessionDownlinkGeneric) {
	clientAddrInfop := downlink.clientAddrInfop
	clientAddrPort := clientAddrInfop.addrPort
	clientPktinfo := clientAddrInfop.pktinfo
	maxClientPacketSize := zerocopy.MaxPacketSizeForAddr(s.mtu, clientAddrPort.Addr())

	serverConnPackerInfo := downlink.serverConnPacker.ServerPackerInfo()
	natConnUnpackerInfo := downlink.natConnUnpacker.ClientUnpackerInfo()
	headroom := zerocopy.UDPRelayHeadroom(serverConnPackerInfo.Headroom, natConnUnpackerInfo.Headroom)

	var (
		packetsSent      uint64
		payloadBytesSent uint64
	)

	packetBuf := make([]byte, headroom.Front+downlink.natConnRecvBufSize+headroom.Rear)
	recvBuf := packetBuf[headroom.Front : headroom.Front+downlink.natConnRecvBufSize]
	var readFailures udpReadErrorBackoff

	for {
		n, _, flags, packetSourceAddrPort, err := downlink.natConn.ReadMsgUDPAddrPort(recvBuf, nil)
		if err != nil {
			if readFailures.shouldRetry(downlink.ctx, err, func(err error) {
				downlink.logger.Warn("Failed to read packet from natConn",
					zap.Stringer("clientAddress", clientAddrPort),
					zap.String("username", downlink.username),
					zap.Uint64("clientSessionID", downlink.csid),
					zap.Stringer("packetSourceAddress", packetSourceAddrPort),
					zap.String("client", downlink.clientName),
					zap.Int("packetLength", n),
					zap.Error(err),
				)
			}) {
				continue
			}
			break
		}
		readFailures.reset()
		err = conn.ParseFlagsForError(flags)
		if err != nil {
			downlink.logger.Warn("Failed to read packet from natConn",
				zap.Stringer("clientAddress", clientAddrPort),
				zap.String("username", downlink.username),
				zap.Uint64("clientSessionID", downlink.csid),
				zap.Stringer("packetSourceAddress", packetSourceAddrPort),
				zap.String("client", downlink.clientName),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			continue
		}

		payloadSourceAddrPort, payloadStart, payloadLength, err := downlink.natConnUnpacker.UnpackInPlace(packetBuf, packetSourceAddrPort, headroom.Front, n)
		if err != nil {
			downlink.logger.Warn("Failed to unpack packet",
				zap.Stringer("clientAddress", clientAddrPort),
				zap.String("username", downlink.username),
				zap.Uint64("clientSessionID", downlink.csid),
				zap.Stringer("packetSourceAddress", packetSourceAddrPort),
				zap.String("client", downlink.clientName),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			continue
		}

		if caip := downlink.clientAddrInfo.Load(); caip != clientAddrInfop {
			clientAddrInfop = caip
			clientAddrPort = caip.addrPort
			clientPktinfo = caip.pktinfo
			maxClientPacketSize = zerocopy.MaxPacketSizeForAddr(s.mtu, clientAddrPort.Addr())
		}

		packetStart, packetLength, err := downlink.serverConnPacker.PackInPlace(packetBuf, payloadSourceAddrPort, payloadStart, payloadLength, maxClientPacketSize)
		if err != nil {
			downlink.logger.Warn("Failed to pack packet",
				zap.Stringer("clientAddress", clientAddrPort),
				zap.String("username", downlink.username),
				zap.Uint64("clientSessionID", downlink.csid),
				zap.Stringer("packetSourceAddress", packetSourceAddrPort),
				zap.String("client", downlink.clientName),
				zap.Stringer("payloadSourceAddress", payloadSourceAddrPort),
				zap.Int("payloadLength", payloadLength),
				zap.Int("maxClientPacketSize", maxClientPacketSize),
				zap.Error(err),
			)
			continue
		}
		reservation, accepted := reserveFullRuntimeTraffic(
			downlink.runtimeSession, RuntimeTrafficDownlink, 1, uint64(payloadLength),
		)
		if !accepted {
			s.dropForbidden.Add(1)
			continue
		}

		func() {
			if reservation != nil {
				defer reservation.Refund()
			}
			written, _, writeErr := downlink.serverConn.WriteMsgUDPAddrPort(packetBuf[packetStart:packetStart+packetLength], clientPktinfo, clientAddrPort)
			err = writeErr
			if err != nil {
				downlink.logger.Warn("Failed to write packet to serverConn",
					zap.Stringer("clientAddress", clientAddrPort),
					zap.String("username", downlink.username),
					zap.Uint64("clientSessionID", downlink.csid),
					zap.Stringer("packetSourceAddress", packetSourceAddrPort),
					zap.String("client", downlink.clientName),
					zap.Stringer("payloadSourceAddress", payloadSourceAddrPort),
					zap.Int("packetLength", packetLength),
					zap.Error(err),
				)
			} else if written != packetLength {
				downlink.logger.Warn("Partial UDP packet write to serverConn was discarded",
					zap.String("username", downlink.username),
					zap.Uint64("clientSessionID", downlink.csid),
					zap.Int("written", written),
					zap.Int("packetLength", packetLength),
				)
			} else if reservation != nil {
				reservation.Commit(uint64(payloadLength))
			} else {
				s.collector.CollectUDPSessionDownlink(downlink.username, 1, uint64(payloadLength))
			}
		}()

		packetsSent++
		payloadBytesSent += uint64(payloadLength)
	}

	downlink.logger.Debug("Finished relay serverConn <- natConn",
		zap.Stringer("clientAddress", clientAddrPort),
		zap.String("username", downlink.username),
		zap.Uint64("clientSessionID", downlink.csid),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("payloadBytesSent", payloadBytesSent),
	)

}

// getQueuedPacket retrieves a queued packet from the pool.
func (s *UDPSessionRelay) getQueuedPacket() *sessionQueuedPacket {
	return s.queuedPacketPool.Get().(*sessionQueuedPacket)
}

// putQueuedPacket puts the queued packet back into the pool.
func (s *UDPSessionRelay) putQueuedPacket(queuedPacket *sessionQueuedPacket) {
	s.queuedPacketPool.Put(queuedPacket)
}

// Stop implements [shadowsocks.Service.Stop].
func (s *UDPSessionRelay) Stop() error {
	for i := range s.listeners {
		lnc := &s.listeners[i]
		if err := lnc.serverConn.SetReadDeadline(conn.ALongTimeAgo); err != nil {
			lnc.logger.Error("Failed to set read deadline on serverConn", zap.Error(err))
		}
	}

	// Wait for serverConn receive goroutines to exit,
	// so there won't be any new sessions added to the table.
	s.mwg.Wait()

	s.mu.Lock()
	for csid, entry := range s.table {
		natConn := entry.state.Swap(entry.serverConn)
		if natConn == nil {
			continue
		}

		if err := natConn.SetReadDeadline(conn.ALongTimeAgo); err != nil {
			entry.logger.Error("Failed to set read deadline on natConn",
				zap.Uint64("clientSessionID", csid),
				zap.Error(err),
			)
		}
	}
	s.mu.Unlock()

	// Wait for all relay goroutines to exit before closing serverConn,
	// so in-flight packets can be written out.
	s.wg.Wait()

	for i := range s.listeners {
		lnc := &s.listeners[i]
		if err := lnc.serverConn.Close(); err != nil {
			lnc.logger.Error("Failed to close serverConn", zap.Error(err))
		}
	}

	s.logger.Info("Stopped UDP session relay service", zap.String("server", s.serverName))
	return nil
}
