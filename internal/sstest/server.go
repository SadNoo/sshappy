package sstest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	ssconn "github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/direct"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

type Server struct {
	config Config
	state  *RuntimeState

	mu       sync.RWMutex
	listener net.Listener
	udpConn  *net.UDPConn
	port     int
	udp      *udpRuntime
	tcp      *tcpRuntime
	tcpOut   *direct.TCPClient
}

func NewServer(config Config, state *RuntimeState) *Server {
	return &Server{
		config: config,
		state:  state,
		udp:    newUDPRuntime(config, state),
		tcp:    newTCPRuntime(),
		tcpOut: direct.NewTCPClient("direct", "tcp", ssconn.DefaultTCPDialer),
	}
}

func (s *Server) Apply(node NodeInfo, users []User) error {
	if err := s.udp.configure(node, users); err != nil {
		return err
	}
	if err := s.tcp.configure(node, users); err != nil {
		return err
	}

	s.mu.Lock()
	needRestart := s.listener == nil || s.port != node.ListenPort
	s.mu.Unlock()

	if needRestart {
		if err := s.Restart(node.ListenPort); err != nil {
			return err
		}
	}
	log.Printf("runtime users applied: node=%d port=%d users=%d", node.ID, node.ListenPort, len(users))
	return nil
}

func (s *Server) Restart(port int) error {
	s.mu.Lock()
	old := s.listener
	oldUDP := s.udpConn
	s.listener = nil
	s.udpConn = nil
	s.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	if oldUDP != nil {
		_ = oldUDP.Close()
	}
	s.udp.closeAll()

	addr := fmt.Sprintf("%s:%d", s.config.ListenHost, port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		_ = ln.Close()
		return err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		_ = ln.Close()
		return err
	}
	tuneUDP(udpConn, s.config)
	s.mu.Lock()
	s.listener = ln
	s.udpConn = udpConn
	s.port = port
	s.mu.Unlock()
	log.Printf("SS2022 Go TCP server listening on %s", addr)
	log.Printf("SS2022 Go UDP server listening on %s", addr)
	log.Printf(
		"SS2022 UDP configured: mtu=%d padding=NoPadding queue=%d relay_batch=%d server_recv_batch=%d requested_read_buffer=%d requested_write_buffer=%d",
		s.config.UDPMTU,
		s.config.UDPQueueSize,
		s.config.UDPRelayBatchSize,
		s.config.UDPServerBatchSize,
		s.config.UDPReadBufferBytes,
		s.config.UDPWriteBufferBytes,
	)
	if readBuffer, writeBuffer, err := udpSocketBufferSizes(udpConn); err != nil {
		log.Printf("debug: inspect UDP listener buffers failed: %v", err)
	} else {
		log.Printf("SS2022 UDP listener buffers effective: read=%d write=%d", readBuffer, writeBuffer)
	}
	go s.udp.serve(udpConn)
	go s.udp.reportMetrics(udpConn, s.currentUDPConn)
	go s.udp.flushTraffic(udpConn, s.currentUDPConn)
	return nil
}

func (s *Server) currentUDPConn() *net.UDPConn {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.udpConn
}

func (s *Server) Serve(ctx context.Context) error {
	for {
		s.mu.RLock()
		ln := s.listener
		s.mu.RUnlock()
		if ln != nil {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}

	go s.tcp.reportMetrics(ctx, time.Duration(s.config.TCPMetricsSeconds)*time.Second)
	for {
		s.mu.RLock()
		ln := s.listener
		s.mu.RUnlock()
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				time.Sleep(50 * time.Millisecond)
				continue
			}
		}
		go s.handleTCP(conn)
	}
}

func (s *Server) handleTCP(client net.Conn) {
	defer client.Close()
	tuneTCP(client)
	tcpClient, ok := client.(*net.TCPConn)
	if !ok {
		return
	}
	clientIP := ""
	if addr, ok := tcpClient.RemoteAddr().(*net.TCPAddr); ok {
		clientIP = addr.IP.String()
	}

	_ = client.SetDeadline(time.Now().Add(time.Duration(s.config.TCPConnectTimeout) * time.Second))
	clientRW, target, initialPayload, user, err := s.tcp.accept(tcpClient)
	if err != nil {
		log.Printf("debug: connection closed from %s: %v", clientIP, err)
		return
	}
	if isDisconnectIP(user, clientIP) ||
		isForbiddenPort(user, int(target.Port())) ||
		isForbiddenHost(user, target.Host()) {
		return
	}
	s.state.AddAliveIP(user.ID, clientIP)
	s.tcp.metrics.accepted.Add(1)
	s.tcp.metrics.active.Add(1)
	defer s.tcp.metrics.active.Add(-1)

	dialStartedAt := time.Now()
	dialContext, cancelDial := context.WithTimeout(
		context.Background(),
		time.Duration(s.config.TCPConnectTimeout)*time.Second,
	)
	remoteRaw, remoteRW, err := s.tcpOut.Dial(dialContext, target, initialPayload)
	cancelDial()
	s.tcp.metrics.dialCount.Add(1)
	s.tcp.metrics.dialNanos.Add(uint64(time.Since(dialStartedAt)))
	if err != nil {
		s.tcp.metrics.dialErrors.Add(1)
		log.Printf("debug: dial target failed from %s: %v", clientIP, err)
		return
	}
	s.tcp.metrics.uploadBytes.Add(uint64(len(initialPayload)))
	defer remoteRaw.Close()
	remote, ok := remoteRaw.(*net.TCPConn)
	if !ok {
		return
	}
	tuneTCP(remote)

	_ = client.SetDeadline(time.Time{})
	_ = remote.SetDeadline(time.Time{})

	done := make(chan struct{}, 2)
	flushBytes := s.config.TrafficFlushBytes
	if flushBytes <= 0 {
		flushBytes = 1 << 20
	}

	uploadWriter := &trafficWriter{
		writer:    remoteRW,
		state:     s.state,
		userID:    user.ID,
		upload:    true,
		threshold: flushBytes,
		pending:   int64(len(initialPayload)),
		counter:   &s.tcp.metrics.uploadBytes,
	}
	downloadWriter := &trafficWriter{
		writer:    clientRW,
		state:     s.state,
		userID:    user.ID,
		threshold: flushBytes,
		counter:   &s.tcp.metrics.downloadBytes,
	}

	go func() {
		_, err := zerocopy.Relay(uploadWriter, clientRW)
		uploadWriter.flush()
		_ = remote.CloseWrite()
		if err != nil && !isExpectedCloseError(err) {
			s.tcp.metrics.relayErrors.Add(1)
			log.Printf("debug: uplink closed from %s: %v", clientIP, err)
		}
		done <- struct{}{}
	}()

	go func() {
		_, err := zerocopy.Relay(downloadWriter, remoteRW)
		downloadWriter.flush()
		_ = tcpClient.CloseWrite()
		if err != nil && !isExpectedCloseError(err) {
			s.tcp.metrics.relayErrors.Add(1)
			log.Printf("debug: downlink closed to %s: %v", clientIP, err)
		}
		done <- struct{}{}
	}()

	<-done
	<-done
}

func tuneTCP(conn net.Conn) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tcp.SetNoDelay(true)
	_ = tcp.SetKeepAlive(true)
	_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	_ = tcp.SetReadBuffer(1 << 20)
	_ = tcp.SetWriteBuffer(1 << 20)
}

func tuneUDP(conn *net.UDPConn, config Config) {
	if config.UDPReadBufferBytes > 0 {
		_ = conn.SetReadBuffer(config.UDPReadBufferBytes)
	}
	if config.UDPWriteBufferBytes > 0 {
		_ = conn.SetWriteBuffer(config.UDPWriteBufferBytes)
	}
}

func isExpectedCloseError(err error) bool {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	text := err.Error()
	return strings.Contains(text, "use of closed network connection") ||
		strings.Contains(text, "connection reset by peer")
}
