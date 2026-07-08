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
)

type registry struct {
	node            NodeInfo
	usersByIdentity map[[16]byte]*User
	ready           bool
}

type Server struct {
	config Config
	state  *RuntimeState

	mu              sync.RWMutex
	registry        registry
	listener        net.Listener
	udpConn         *net.UDPConn
	port            int
	udpMu           sync.Mutex
	udpAssociations map[udpAssociationKey]*udpAssociation
}

type udpAssociationKey struct {
	clientAddr      string
	userID          int
	clientSessionID uint64
	targetHost      string
	targetPort      int
}

type udpAssociation struct {
	key             udpAssociationKey
	target          TargetAddress
	user            *User
	clientAddr      *net.UDPAddr
	clientSessionID uint64
	serverSessionID uint64
	packetID        uint64
	conn            *net.UDPConn
	lastSeen        time.Time
}

func NewServer(config Config, state *RuntimeState) *Server {
	return &Server{config: config, state: state, udpAssociations: make(map[udpAssociationKey]*udpAssociation)}
}

func (s *Server) Apply(node NodeInfo, users []User) error {
	usersByIdentity := make(map[[16]byte]*User, len(users))
	for i := range users {
		usersByIdentity[users[i].IdentityHash] = &users[i]
	}

	s.mu.Lock()
	s.registry = registry{node: node, usersByIdentity: usersByIdentity, ready: true}
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
	s.closeUDPAssociations()

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
	s.mu.Lock()
	s.listener = ln
	s.udpConn = udpConn
	s.port = port
	s.mu.Unlock()
	log.Printf("SS2022 Go TCP server listening on %s", addr)
	log.Printf("SS2022 Go UDP server listening on %s", addr)
	go s.serveUDP(udpConn)
	return nil
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
	clientIP := ""
	if addr, ok := client.RemoteAddr().(*net.TCPAddr); ok {
		clientIP = addr.IP.String()
	}

	s.mu.RLock()
	reg := s.registry
	s.mu.RUnlock()
	if !reg.ready {
		return
	}

	_ = client.SetDeadline(time.Now().Add(time.Duration(s.config.TCPConnectTimeout) * time.Second))
	req, err := readClientRequest(client, reg.usersByIdentity, reg.node.ServerKey)
	if err != nil {
		log.Printf("debug: connection closed from %s: %v", clientIP, err)
		return
	}
	user := req.User
	if isDisconnectIP(user, clientIP) || isForbiddenPort(user, req.Target.Port) || isForbiddenHost(user, req.Target.Host) {
		return
	}
	s.state.AddAliveIP(user.ID, clientIP)

	remote, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", req.Target.Host, req.Target.Port), time.Duration(s.config.TCPConnectTimeout)*time.Second)
	if err != nil {
		log.Printf("debug: dial target failed from %s: %v", clientIP, err)
		return
	}
	defer remote.Close()
	tuneTCP(remote)

	_ = client.SetDeadline(time.Time{})
	_ = remote.SetDeadline(time.Time{})

	var uploadInitial int64
	if len(req.InitialPayload) > 0 {
		if err := writeFull(remote, req.InitialPayload); err != nil {
			return
		}
		uploadInitial = int64(len(req.InitialPayload))
	}

	done := make(chan struct{}, 2)
	var upload, download int64
	var mu sync.Mutex

	go func() {
		defer func() { done <- struct{}{} }()
		localUpload := uploadInitial
		lenCipher := make([]byte, 2+tagLen)
		payloadCipher := make([]byte, tcpMaxPayloadSize+tagLen)
		for {
			payload, nextPayloadCipher, err := readClientPayloadBuffered(client, req.Decryptor, lenCipher, payloadCipher)
			payloadCipher = nextPayloadCipher
			if err != nil {
				if !isExpectedCloseError(err) {
					log.Printf("debug: uplink closed from %s: %v", clientIP, err)
				}
				break
			}
			if err := writeFull(remote, payload); err != nil {
				break
			}
			localUpload += int64(len(payload))
		}
		mu.Lock()
		upload += localUpload
		mu.Unlock()
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, tcpMaxPayloadSize)
		writeBuf := make([]byte, 0, tcpMaxPayloadSize+2+2*tagLen+saltLen+64)
		var encryptor *aeadStream
		var localDownload int64
		for {
			n, err := remote.Read(buf)
			if n > 0 {
				chunk := buf[:n]
				if encryptor == nil {
					encryptor, writeBuf, err = writeResponseHeaderAndPayload(client, user.UserKey, req.RequestSalt, chunk, writeBuf)
				} else {
					writeBuf, err = writeResponsePayload(client, encryptor, chunk, writeBuf)
				}
				if err != nil {
					break
				}
				localDownload += int64(n)
			}
			if err != nil {
				break
			}
		}
		mu.Lock()
		download += localDownload
		mu.Unlock()
	}()

	<-done
	_ = client.Close()
	_ = remote.Close()
	<-done

	mu.Lock()
	finalUpload := upload
	finalDownload := download
	mu.Unlock()
	s.state.AddTraffic(user.ID, finalUpload, finalDownload)
}

func (s *Server) serveUDP(conn *net.UDPConn) {
	buf := make([]byte, udpMaxPacketSize)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		go s.handleUDPDatagram(conn, data, addr)
	}
}

func (s *Server) handleUDPDatagram(inbound *net.UDPConn, data []byte, clientAddr *net.UDPAddr) {
	s.mu.RLock()
	reg := s.registry
	currentInbound := s.udpConn
	s.mu.RUnlock()
	if !reg.ready || inbound != currentInbound {
		return
	}
	clientIP := clientAddr.IP.String()
	packet, err := decryptUDPClientPacket(data, reg.usersByIdentity, reg.node.ServerKey)
	if err != nil {
		if !isExpectedCloseError(err) {
			log.Printf("debug: udp packet dropped from %s: %v", clientIP, err)
		}
		return
	}
	user := packet.User
	if isDisconnectIP(user, clientIP) || isForbiddenPort(user, packet.Target.Port) || isForbiddenHost(user, packet.Target.Host) {
		return
	}
	s.state.AddAliveIP(user.ID, clientIP)
	s.state.AddTraffic(user.ID, int64(len(packet.Payload)), 0)

	assoc, err := s.getUDPAssociation(packet, clientAddr)
	if err != nil {
		log.Printf("debug: udp target open failed from %s: %v", clientIP, err)
		return
	}
	assoc.packetID = packet.PacketID
	assoc.lastSeen = time.Now()
	if _, err := assoc.conn.Write(packet.Payload); err != nil && !isExpectedCloseError(err) {
		log.Printf("debug: udp target write failed from %s: %v", clientIP, err)
	}
	s.cleanupUDPAssociations()
}

func (s *Server) getUDPAssociation(packet *UDPClientPacket, clientAddr *net.UDPAddr) (*udpAssociation, error) {
	key := udpAssociationKey{
		clientAddr:      clientAddr.String(),
		userID:          packet.User.ID,
		clientSessionID: packet.ClientSessionID,
		targetHost:      packet.Target.Host,
		targetPort:      packet.Target.Port,
	}
	s.udpMu.Lock()
	if assoc := s.udpAssociations[key]; assoc != nil {
		s.udpMu.Unlock()
		return assoc, nil
	}
	s.udpMu.Unlock()

	remoteAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", packet.Target.Host, packet.Target.Port))
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, remoteAddr)
	if err != nil {
		return nil, err
	}
	assoc := &udpAssociation{
		key:             key,
		target:          packet.Target,
		user:            packet.User,
		clientAddr:      clientAddr,
		clientSessionID: packet.ClientSessionID,
		serverSessionID: makeUDPServerSessionID(),
		packetID:        packet.PacketID,
		conn:            conn,
		lastSeen:        time.Now(),
	}

	s.udpMu.Lock()
	if existing := s.udpAssociations[key]; existing != nil {
		s.udpMu.Unlock()
		_ = conn.Close()
		return existing, nil
	}
	s.udpAssociations[key] = assoc
	s.udpMu.Unlock()
	go s.readUDPAssociation(assoc)
	return assoc, nil
}

func (s *Server) readUDPAssociation(assoc *udpAssociation) {
	buf := make([]byte, udpMaxPacketSize)
	for {
		n, err := assoc.conn.Read(buf)
		if err != nil {
			return
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		s.handleUDPResponse(assoc, payload)
	}
}

func (s *Server) handleUDPResponse(assoc *udpAssociation, payload []byte) {
	s.mu.RLock()
	inbound := s.udpConn
	s.mu.RUnlock()
	if inbound == nil {
		return
	}
	assoc.lastSeen = time.Now()
	response, err := encryptUDPServerPacket(assoc.user, assoc.target, payload, assoc.clientSessionID, assoc.packetID, assoc.serverSessionID)
	if err != nil {
		log.Printf("debug: udp response encrypt failed: %v", err)
		return
	}
	if _, err := inbound.WriteToUDP(response, assoc.clientAddr); err != nil && !isExpectedCloseError(err) {
		log.Printf("debug: udp response write failed: %v", err)
		return
	}
	s.state.AddTraffic(assoc.user.ID, 0, int64(len(payload)))
	s.state.AddAliveIP(assoc.user.ID, assoc.clientAddr.IP.String())
}

func (s *Server) cleanupUDPAssociations() {
	cutoff := time.Now().Add(-time.Duration(s.config.UDPIdleTimeout) * time.Second)
	s.udpMu.Lock()
	defer s.udpMu.Unlock()
	for key, assoc := range s.udpAssociations {
		if assoc.lastSeen.Before(cutoff) {
			_ = assoc.conn.Close()
			delete(s.udpAssociations, key)
		}
	}
}

func (s *Server) closeUDPAssociations() {
	s.udpMu.Lock()
	defer s.udpMu.Unlock()
	for key, assoc := range s.udpAssociations {
		_ = assoc.conn.Close()
		delete(s.udpAssociations, key)
	}
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
