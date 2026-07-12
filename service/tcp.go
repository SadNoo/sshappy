package service

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/database64128/shadowsocks-go"
	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/netio"
	"github.com/database64128/shadowsocks-go/router"
	"github.com/database64128/shadowsocks-go/stats"
	"go.uber.org/zap"
)

const (
	defaultInitialPayloadWaitBufferSize = 1440
	defaultInitialPayloadWaitTimeout    = 250 * time.Millisecond
	defaultHandshakeTimeout             = 10 * time.Second
	defaultMaxConcurrentHandshakes      = 1024
	defaultTCPTrafficFlushInterval      = 30 * time.Second
)

// tcpRelayListener configures the TCP listener for a relay service.
type tcpRelayListener struct {
	logger                       *zap.Logger
	listener                     *net.TCPListener
	listenConfig                 conn.ListenConfig
	waitForInitialPayload        bool
	handshakeTimeout             time.Duration
	handshakeSlots               chan struct{}
	maxConnectionsPerUser        int
	trafficFlushInterval         time.Duration
	initialPayloadWaitTimeout    time.Duration
	initialPayloadWaitBufferSize int
	network                      string
	address                      string
}

// TCPRelay is a relay service for TCP traffic.
//
// When started, the relay service accepts incoming TCP connections on the server,
// and dispatches them to a client selected by the router.
//
// TCPRelay implements the Service interface.
type TCPRelay struct {
	serverIndex           int
	serverName            string
	listeners             []tcpRelayListener
	acceptWg              sync.WaitGroup
	server                netio.StreamServer
	collector             stats.Collector
	observer              RuntimeObserver
	router                *router.Router
	logger                *zap.Logger
	metricsWg             sync.WaitGroup
	handlerWg             sync.WaitGroup
	connectionsMu         sync.Mutex
	connections           map[net.Conn]struct{}
	userConnectionsMu     sync.Mutex
	connectionsByUser     map[string]int
	lastLimitedUser       string
	stopping              bool
	acceptedConnections   atomic.Uint64
	activeConnections     atomic.Int64
	activeHandshakes      atomic.Int64
	handshakeTimeouts     atomic.Uint64
	handshakeFailures     atomic.Uint64
	rejectedCapacity      atomic.Uint64
	rejectedUserLimit     atomic.Uint64
	activeUserConnections atomic.Int64
	peakUserConnections   atomic.Uint64
	targetDialAttempts    atomic.Uint64
	targetDialCompleted   atomic.Uint64
	targetDialErrors      atomic.Uint64
	targetDialNanos       atomic.Uint64
	relayErrors           atomic.Uint64
	uplinkBytes           atomic.Uint64
	downlinkBytes         atomic.Uint64
}

func NewTCPRelay(
	serverIndex int,
	serverName string,
	listeners []tcpRelayListener,
	server netio.StreamServer,
	collector stats.Collector,
	observer RuntimeObserver,
	router *router.Router,
	logger *zap.Logger,
) *TCPRelay {
	return &TCPRelay{
		serverIndex:       serverIndex,
		serverName:        serverName,
		listeners:         listeners,
		server:            server,
		collector:         collector,
		observer:          observer,
		router:            router,
		logger:            logger,
		connections:       make(map[net.Conn]struct{}),
		connectionsByUser: make(map[string]int),
	}
}

func (s *TCPRelay) reserveUserConnection(username string, limit int) bool {
	s.userConnectionsMu.Lock()
	defer s.userConnectionsMu.Unlock()
	if limit > 0 && s.connectionsByUser[username] >= limit {
		s.lastLimitedUser = username
		s.rejectedUserLimit.Add(1)
		return false
	}
	s.connectionsByUser[username]++
	active := s.activeUserConnections.Add(1)
	for peak := s.peakUserConnections.Load(); uint64(active) > peak; peak = s.peakUserConnections.Load() {
		if s.peakUserConnections.CompareAndSwap(peak, uint64(active)) {
			break
		}
	}
	return true
}

func (s *TCPRelay) releaseUserConnection(username string) {
	s.userConnectionsMu.Lock()
	remaining := s.connectionsByUser[username] - 1
	if remaining <= 0 {
		delete(s.connectionsByUser, username)
	} else {
		s.connectionsByUser[username] = remaining
	}
	s.userConnectionsMu.Unlock()
	s.activeUserConnections.Add(-1)
}

var _ shadowsocks.Service = (*TCPRelay)(nil)

// ZapField implements [shadowsocks.Service.ZapField].
func (s *TCPRelay) ZapField() zap.Field {
	return zap.String("serverTCPRelay", s.serverName)
}

// Start implements [shadowsocks.Service.Start].
func (s *TCPRelay) Start(ctx context.Context) error {
	for i := range s.listeners {
		index := i
		lnc := &s.listeners[index]

		l, _, err := lnc.listenConfig.ListenTCP(ctx, lnc.network, lnc.address)
		if err != nil {
			return err
		}
		lnc.listener = l
		lnc.address = l.Addr().String()
		lnc.logger = s.logger.With(
			zap.String("server", s.serverName),
			zap.Int("listener", index),
			zap.String("listenAddress", lnc.address),
		)

		s.acceptWg.Go(func() {
			for {
				clientConn, err := lnc.listener.AcceptTCP()
				if err != nil {
					if errors.Is(err, os.ErrDeadlineExceeded) {
						break
					}
					lnc.logger.Error("Failed to accept TCP connection", zap.Error(err))
					continue
				}
				s.acceptedConnections.Add(1)
				select {
				case lnc.handshakeSlots <- struct{}{}:
					s.activeHandshakes.Add(1)
				default:
					s.rejectedCapacity.Add(1)
					_ = clientConn.Close()
					continue
				}
				if !s.registerConnection(clientConn) {
					<-lnc.handshakeSlots
					s.activeHandshakes.Add(-1)
					_ = clientConn.Close()
					continue
				}
				s.activeConnections.Add(1)
				s.handlerWg.Go(func() {
					s.handleConn(ctx, lnc, clientConn)
				})
			}
		})

		lnc.logger.Info("Started TCP relay service listener")
	}
	s.metricsWg.Go(func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		var lastRejectedUserLimit uint64
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.userConnectionsMu.Lock()
				lastLimitedUser := s.lastLimitedUser
				var busiestUser string
				var busiestUserConnections int
				for username, connections := range s.connectionsByUser {
					if connections > busiestUserConnections {
						busiestUser = username
						busiestUserConnections = connections
					}
				}
				s.userConnectionsMu.Unlock()
				rejectedUserLimit := s.rejectedUserLimit.Load()
				maxConnectionsPerUser := 0
				if len(s.listeners) > 0 {
					maxConnectionsPerUser = s.listeners[0].maxConnectionsPerUser
				}
				s.logger.Info("TCP relay metrics",
					zap.String("server", s.serverName),
					zap.Uint64("accepted", s.acceptedConnections.Load()),
					zap.Int64("activeConnections", s.activeConnections.Load()),
					zap.Int64("activeHandshakes", s.activeHandshakes.Load()),
					zap.Uint64("handshakeTimeouts", s.handshakeTimeouts.Load()),
					zap.Uint64("handshakeFailures", s.handshakeFailures.Load()),
					zap.Uint64("rejectedCapacity", s.rejectedCapacity.Load()),
					zap.Uint64("rejectedUserLimit", rejectedUserLimit),
					zap.Int64("activeUserConnections", s.activeUserConnections.Load()),
					zap.Uint64("peakUserConnections", s.peakUserConnections.Load()),
					zap.String("busiestUser", busiestUser),
					zap.Int("busiestUserConnections", busiestUserConnections),
					zap.String("lastLimitedUser", lastLimitedUser),
					zap.Int("maxConnectionsPerUser", maxConnectionsPerUser),
					zap.Uint64("targetDialAttempts", s.targetDialAttempts.Load()),
					zap.Uint64("targetDialErrors", s.targetDialErrors.Load()),
					zap.Duration("averageTargetDialLatency", averageDuration(s.targetDialNanos.Load(), s.targetDialCompleted.Load())),
					zap.Uint64("relayErrors", s.relayErrors.Load()),
					zap.Uint64("uplinkBytes", s.uplinkBytes.Load()),
					zap.Uint64("downlinkBytes", s.downlinkBytes.Load()),
				)
				if delta := rejectedUserLimit - lastRejectedUserLimit; delta > 0 {
					s.logger.Warn("TCP connections rejected by per-user limit",
						zap.Uint64("rejectedSinceLastReport", delta),
						zap.Uint64("rejectedTotal", rejectedUserLimit),
						zap.String("username", lastLimitedUser),
						zap.Int("maxConnectionsPerUser", maxConnectionsPerUser),
					)
				}
				lastRejectedUserLimit = rejectedUserLimit
			}
		}
	})
	return nil
}

// handleConn handles an accepted TCP connection.
func (s *TCPRelay) handleConn(ctx context.Context, lnc *tcpRelayListener, clientTCPConn *net.TCPConn) {
	handshakeActive := true
	releaseHandshake := func() {
		if handshakeActive {
			<-lnc.handshakeSlots
			s.activeHandshakes.Add(-1)
			handshakeActive = false
		}
	}
	defer releaseHandshake()
	defer s.activeConnections.Add(-1)
	defer s.unregisterConnection(clientTCPConn)
	var clientConn netio.Conn
	defer func() {
		if clientConn != nil {
			_ = clientConn.Close()
		} else {
			_ = clientTCPConn.Close()
		}
	}()

	// Get client address.
	clientAddrPort := clientTCPConn.RemoteAddr().(*net.TCPAddr).AddrPort()
	clientAddress := clientAddrPort.String()
	logger := lnc.logger.With(
		zap.String("clientAddress", clientAddress),
	)

	// Handshake.
	if err := clientTCPConn.SetReadDeadline(time.Now().Add(lnc.handshakeTimeout)); err != nil {
		logger.Warn("Failed to set handshake read deadline", zap.Error(err))
		return
	}
	req, err := s.server.HandleStream(clientTCPConn, logger)
	if err != nil {
		if err == netio.ErrHandleStreamDone {
			logger.Debug("Handled TCP connection without bidirectional copy")
			return
		}
		s.handshakeFailures.Add(1)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			s.handshakeTimeouts.Add(1)
		}
		logger.Debug("Failed to complete handshake with client", zap.Error(err))
		return
	}
	releaseHandshake()
	if err := clientTCPConn.SetReadDeadline(time.Time{}); err != nil {
		logger.Warn("Failed to clear handshake read deadline", zap.Error(err))
		return
	}
	if s.observer != nil && !s.observer.Accept("tcp", req.Username, clientAddrPort, req.Addr) {
		logger.Debug("Rejected TCP connection by runtime policy", zap.String("username", req.Username))
		return
	}
	if !s.reserveUserConnection(req.Username, lnc.maxConnectionsPerUser) {
		logger.Debug("Rejected TCP connection by per-user limit",
			zap.String("username", req.Username),
			zap.Int("maxConnectionsPerUser", lnc.maxConnectionsPerUser),
		)
		if err := req.Abort(conn.DialResult{Code: conn.DialResultCodeEACCES}); err != nil {
			logger.Debug("Failed to abort connection rejected by per-user limit", zap.Error(err))
		}
		return
	}
	defer s.releaseUserConnection(req.Username)
	if s.observer != nil {
		s.observer.Observe("tcp", req.Username, clientAddrPort)
	}

	// Convert target address to string once for log messages.
	targetAddress := req.Addr.String()

	// Route.
	c, err := s.router.GetTCPClient(ctx, router.RequestInfo{
		ServerIndex:    s.serverIndex,
		Username:       req.Username,
		SourceAddrPort: clientAddrPort,
		TargetAddr:     req.Addr,
	})
	if err != nil {
		logger.Warn("Failed to get TCP client for client connection",
			zap.String("username", req.Username),
			zap.String("targetAddress", targetAddress),
			zap.Error(err),
		)

		dialResult := router.DialResultFromError(err)
		if err = req.Abort(dialResult); err != nil {
			logger.Warn("Failed to abort pending connection",
				zap.String("username", req.Username),
				zap.String("targetAddress", targetAddress),
				zap.Error(err),
			)
		}
		return
	}

	// Create dialer.
	dialer, clientInfo := c.NewStreamDialer()

	// Create logger with new fields.
	logger = logger.With(
		zap.String("username", req.Username),
		zap.String("targetAddress", targetAddress),
		zap.String("client", clientInfo.Name),
	)

	// Wait for initial payload if all of the following are true:
	// 1. not disabled
	// 2. server does not have native support
	// 3. server did not return initial payload
	// 4. client has native support
	if len(req.Payload) == 0 && clientInfo.NativeInitialPayload && lnc.waitForInitialPayload {
		clientConn, err = req.PendingConn.Proceed()
		if err != nil {
			logger.Warn("Failed to proceed with pending connection", zap.Error(err))
			return
		}

		req.Payload = make([]byte, lnc.initialPayloadWaitBufferSize)

		if err = clientConn.SetReadDeadline(time.Now().Add(lnc.initialPayloadWaitTimeout)); err != nil {
			logger.Error("Failed to set read deadline to initial payload wait timeout", zap.Error(err))
			return
		}

		payloadLength, err := clientConn.Read(req.Payload)
		switch {
		case err == nil:
			if ce := logger.Check(zap.DebugLevel, "Got initial payload"); ce != nil {
				ce.Write(
					zap.Int("payloadLength", payloadLength),
				)
			}

		case err == io.EOF:
			if ce := logger.Check(zap.DebugLevel, "Got initial payload and EOF"); ce != nil {
				ce.Write(
					zap.Int("payloadLength", payloadLength),
				)
			}

		case errors.Is(err, os.ErrDeadlineExceeded):
			if ce := logger.Check(zap.DebugLevel, "Initial payload wait timed out"); ce != nil {
				ce.Write()
			}

		default:
			logger.Warn("Failed to read initial payload", zap.Error(err))
			return
		}

		req.Payload = req.Payload[:payloadLength]

		if err = clientConn.SetReadDeadline(time.Time{}); err != nil {
			logger.Error("Failed to reset read deadline", zap.Error(err))
			return
		}
	}

	// Create remote connection.
	dialStartedAt := time.Now()
	s.targetDialAttempts.Add(1)
	remoteConn, err := dialer.DialStream(ctx, req.Addr, req.Payload)
	s.targetDialNanos.Add(uint64(time.Since(dialStartedAt)))
	s.targetDialCompleted.Add(1)
	if err != nil {
		s.targetDialErrors.Add(1)
		logger.Debug("Failed to create remote connection",
			zap.Int("initialPayloadLength", len(req.Payload)),
			zap.Error(err),
		)
		if clientConn == nil {
			dialResult := conn.DialResultFromError(err)
			if err = req.Abort(dialResult); err != nil {
				logger.Warn("Failed to abort pending connection", zap.Error(err))
			}
		}
		return
	}
	defer remoteConn.Close()
	if !s.registerConnection(remoteConn) {
		return
	}
	defer s.unregisterConnection(remoteConn)

	if clientConn == nil {
		clientConn, err = req.PendingConn.Proceed()
		if err != nil {
			logger.Warn("Failed to proceed with pending connection", zap.Error(err))
			return
		}
	}

	logger.Debug("Bidirectional copy started",
		zap.Int("initialPayloadLength", len(req.Payload)),
	)

	accounting := newTCPSessionAccounting(s, req.Username, uint64(len(req.Payload)))
	stopAccounting := accounting.start(lnc.trafficFlushInterval)
	defer stopAccounting()

	// Count bytes only after a successful write to each side.
	meteredClientConn := meteredTCPConn{Conn: clientConn, written: &accounting.downlink}
	meteredRemoteConn := meteredTCPConn{Conn: remoteConn, written: &accounting.uplink}
	nl2r, nr2l, err := netio.BidirectionalCopy(&meteredClientConn, &meteredRemoteConn)
	nl2r += int64(len(req.Payload))
	if err != nil {
		s.relayErrors.Add(1)
		logger.Debug("Bidirectional copy failed",
			zap.Int64("nl2r", nl2r),
			zap.Int64("nr2l", nr2l),
			zap.Error(err),
		)
		return
	}

	logger.Debug("Bidirectional copy completed",
		zap.Int64("nl2r", nl2r),
		zap.Int64("nr2l", nr2l),
	)
}

type meteredTCPConn struct {
	netio.Conn
	written *atomic.Uint64
}

func (c *meteredTCPConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.written.Add(uint64(n))
	return n, err
}

type tcpSessionAccounting struct {
	relay    *TCPRelay
	username string
	uplink   atomic.Uint64
	downlink atomic.Uint64
}

func newTCPSessionAccounting(relay *TCPRelay, username string, initialUplink uint64) *tcpSessionAccounting {
	a := &tcpSessionAccounting{relay: relay, username: username}
	a.uplink.Store(initialUplink)
	return a
}

func (a *tcpSessionAccounting) start(interval time.Duration) func() {
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				a.flush()
			}
		}
	})
	return func() {
		close(done)
		wg.Wait()
		a.flush()
	}
}

func (a *tcpSessionAccounting) flush() {
	uplink := a.uplink.Swap(0)
	downlink := a.downlink.Swap(0)
	if uplink == 0 && downlink == 0 {
		return
	}
	a.relay.uplinkBytes.Add(uplink)
	a.relay.downlinkBytes.Add(downlink)
	a.relay.collector.CollectTCPSession(a.username, downlink, uplink)
}

func (s *TCPRelay) registerConnection(connection net.Conn) bool {
	s.connectionsMu.Lock()
	defer s.connectionsMu.Unlock()
	if s.stopping {
		return false
	}
	s.connections[connection] = struct{}{}
	return true
}

func (s *TCPRelay) unregisterConnection(connection net.Conn) {
	s.connectionsMu.Lock()
	delete(s.connections, connection)
	s.connectionsMu.Unlock()
}

func averageDuration(totalNanos, count uint64) time.Duration {
	if count == 0 {
		return 0
	}
	return time.Duration(totalNanos / count)
}

// Stop implements [shadowsocks.Service.Stop].
func (s *TCPRelay) Stop() error {
	s.connectionsMu.Lock()
	s.stopping = true
	connections := make([]net.Conn, 0, len(s.connections))
	for connection := range s.connections {
		connections = append(connections, connection)
	}
	s.connectionsMu.Unlock()

	for i := range s.listeners {
		lnc := &s.listeners[i]
		if err := lnc.listener.SetDeadline(conn.ALongTimeAgo); err != nil {
			lnc.logger.Error("Failed to set deadline on listener", zap.Error(err))
		}
	}

	s.acceptWg.Wait()
	for _, connection := range connections {
		_ = connection.Close()
	}
	s.handlerWg.Wait()
	s.metricsWg.Wait()

	for i := range s.listeners {
		lnc := &s.listeners[i]
		if err := lnc.listener.Close(); err != nil {
			lnc.logger.Error("Failed to close listener", zap.Error(err))
		}
	}

	s.logger.Info("Stopped TCP relay service", zap.String("server", s.serverName))
	return nil
}
