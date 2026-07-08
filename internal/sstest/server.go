package sstest

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
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

	mu       sync.RWMutex
	registry registry
	listener net.Listener
	port     int
}

func NewServer(config Config, state *RuntimeState) *Server {
	return &Server{config: config, state: state}
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
	s.listener = nil
	s.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}

	addr := fmt.Sprintf("%s:%d", s.config.ListenHost, port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = ln
	s.port = port
	s.mu.Unlock()
	log.Printf("SS2022 Go TCP server listening on %s", addr)
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
	clientIP := ""
	if addr, ok := client.RemoteAddr().(*net.TCPAddr); ok {
		clientIP = addr.IP.String()
	}
	deadline := time.Duration(s.config.TCPIdleTimeout) * time.Second

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
		for {
			_ = client.SetReadDeadline(time.Now().Add(deadline))
			payload, err := readClientPayload(client, req.Decryptor)
			if err != nil {
				if err != io.EOF {
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
		var encryptor *aeadStream
		var localDownload int64
		for {
			_ = remote.SetReadDeadline(time.Now().Add(deadline))
			n, err := remote.Read(buf)
			if n > 0 {
				chunk := buf[:n]
				if encryptor == nil {
					encryptor, err = writeResponseHeaderAndPayload(client, user.UserKey, req.RequestSalt, chunk)
				} else {
					err = writeResponsePayload(client, encryptor, chunk)
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

func writeFull(conn net.Conn, payload []byte) error {
	for len(payload) > 0 {
		n, err := conn.Write(payload)
		if err != nil {
			return err
		}
		payload = payload[n:]
	}
	return nil
}
