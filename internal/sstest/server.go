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
}

func NewServer(config Config, state *RuntimeState) *Server {
	return &Server{
		config: config,
		state:  state,
		udp:    newUDPRuntime(config, state),
		tcp:    newTCPRuntime(),
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
	if isDisconnectIP(user, clientIP) || isForbiddenPort(user, target.Port) || isForbiddenHost(user, target.Host) {
		return
	}
	s.state.AddAliveIP(user.ID, clientIP)

	remoteConn, err := net.DialTimeout(
		"tcp",
		fmt.Sprintf("%s:%d", target.Host, target.Port),
		time.Duration(s.config.TCPConnectTimeout)*time.Second,
	)
	if err != nil {
		log.Printf("debug: dial target failed from %s: %v", clientIP, err)
		return
	}
	defer remoteConn.Close()
	tuneTCP(remoteConn)
	remote, ok := remoteConn.(*net.TCPConn)
	if !ok {
		return
	}

	_ = client.SetDeadline(time.Time{})
	_ = remote.SetDeadline(time.Time{})

	if len(initialPayload) > 0 {
		if err := writeFull(remote, initialPayload); err != nil {
			return
		}
	}

	done := make(chan struct{}, 2)
	flushBytes := s.config.TrafficFlushBytes
	if flushBytes <= 0 {
		flushBytes = 1 << 20
	}

	remoteRW := direct.NewDirectStreamReadWriter(remote)
	uploadWriter := &trafficWriter{
		writer:    remoteRW,
		state:     s.state,
		userID:    user.ID,
		upload:    true,
		threshold: flushBytes,
		pending:   int64(len(initialPayload)),
	}
	downloadWriter := &trafficWriter{
		writer:    clientRW,
		state:     s.state,
		userID:    user.ID,
		threshold: flushBytes,
	}

	go func() {
		_, err := zerocopy.Relay(uploadWriter, clientRW)
		uploadWriter.flush()
		_ = remote.CloseWrite()
		if err != nil && !isExpectedCloseError(err) {
			log.Printf("debug: uplink closed from %s: %v", clientIP, err)
		}
		done <- struct{}{}
	}()

	go func() {
		_, err := zerocopy.Relay(downloadWriter, remoteRW)
		downloadWriter.flush()
		_ = tcpClient.CloseWrite()
		if err != nil && !isExpectedCloseError(err) {
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

func writeFull(conn net.Conn, payload []byte) error {
	for len(payload) > 0 {
		n, err := conn.Write(payload)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}

func isExpectedCloseError(err error) bool {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	text := err.Error()
	return strings.Contains(text, "use of closed network connection") ||
		strings.Contains(text, "connection reset by peer")
}
