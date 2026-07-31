package dns

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/direct"
	"github.com/database64128/shadowsocks-go/netio"
	"github.com/database64128/shadowsocks-go/netiotest"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"golang.org/x/net/dns/dnsmessage"
)

type closeOrderPacker struct {
	server      netip.AddrPort
	calls       int
	secondQuery chan []byte
	exited      chan struct{}
}

func (*closeOrderPacker) ClientPackerInfo() zerocopy.ClientPackerInfo {
	return zerocopy.ClientPackerInfo{}
}

func (p *closeOrderPacker) PackInPlace(ctx context.Context, b []byte, _ conn.Addr, payloadStart, payloadLen int) (netip.AddrPort, int, int, error) {
	p.calls++
	if p.calls == 2 {
		p.secondQuery <- bytes.Clone(b[payloadStart : payloadStart+payloadLen])
		defer close(p.exited)
		<-ctx.Done()
		return netip.AddrPort{}, 0, 0, ctx.Err()
	}
	return p.server, payloadStart, payloadLen, nil
}

type closeOrderUDPClient struct {
	packer                 *closeOrderPacker
	closed                 bool
	closedBeforeSenderExit bool
}

func (c *closeOrderUDPClient) Info() zerocopy.UDPClientInfo {
	return zerocopy.UDPClientInfo{Name: "close-order"}
}

func (c *closeOrderUDPClient) NewSession(context.Context) (zerocopy.UDPClientSessionInfo, zerocopy.UDPClientSession, error) {
	info := zerocopy.UDPClientSessionInfo{
		Name:         "close-order",
		MTU:          1500,
		ListenConfig: conn.DefaultUDPClientListenConfig,
	}
	return info, zerocopy.UDPClientSession{
		MaxPacketSize: 1500,
		Packer:        c.packer,
		Unpacker:      direct.DirectPacketClientUnpacker{},
		Close: func() error {
			c.closed = true
			select {
			case <-c.packer.exited:
			default:
				c.closedBeforeSenderExit = true
			}
			return nil
		},
	}, nil
}

func testResolver(t *testing.T, name string, serverAddrPort netip.AddrPort, tcpClient netio.StreamClient, udpClient zerocopy.UDPClient, logger *zap.Logger) {
	r := NewResolver(name, defaultCacheSize, serverAddrPort, tcpClient, udpClient, logger)
	ctx := t.Context()

	// Uncached lookup.
	uncachedResult, err := r.Lookup(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(uncachedResult.a) == 0 {
		t.Error("Expected at least one IPv4 address")
	}
	if len(uncachedResult.aaaa) == 0 {
		t.Error("Expected at least one IPv6 address")
	}

	// Cached lookup.
	cachedResult, err := r.Lookup(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}

	if uncachedResult.expiresAt != cachedResult.expiresAt {
		t.Error("TTL mismatch")
	}
}

func TestResolver(t *testing.T) {
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	t.Run("UDP", func(t *testing.T) {
		server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer server.Close()
		if err = server.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		errCh := make(chan error, 1)
		go func() {
			buf := make([]byte, 1232)
			for range 2 {
				n, peer, err := server.ReadFromUDPAddrPort(buf)
				if err != nil {
					errCh <- err
					return
				}
				response, err := testDNSResponse(buf[:n])
				if err == nil {
					_, err = server.WriteToUDPAddrPort(response, peer)
				}
				if err != nil {
					errCh <- err
					return
				}
			}
			errCh <- nil
		}()
		serverAddrPort := server.LocalAddr().(*net.UDPAddr).AddrPort()
		udpClient := direct.NewDirectUDPClient("direct", "ip4", 1500, conn.DefaultUDPClientListenConfig)
		testResolver(t, "UDP", serverAddrPort, nil, udpClient, logger)
		if err = <-errCh; err != nil {
			t.Fatal(err)
		}
	})

	t.Run("TCP", func(t *testing.T) {
		listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		errCh := make(chan error, 1)
		go func() {
			connection, err := listener.AcceptTCP()
			if err != nil {
				errCh <- err
				return
			}
			defer connection.Close()
			if err = connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				errCh <- err
				return
			}
			length := make([]byte, 2)
			for range 2 {
				if _, err = io.ReadFull(connection, length); err != nil {
					errCh <- err
					return
				}
				query := make([]byte, binary.BigEndian.Uint16(length))
				if _, err = io.ReadFull(connection, query); err != nil {
					errCh <- err
					return
				}
				response, responseErr := testDNSResponse(query)
				if responseErr != nil {
					errCh <- responseErr
					return
				}
				binary.BigEndian.PutUint16(length, uint16(len(response)))
				if _, err = connection.Write(append(length, response...)); err != nil {
					errCh <- err
					return
				}
			}
			errCh <- nil
		}()
		serverAddrPort := listener.Addr().(*net.TCPAddr).AddrPort()
		tcpClientConfig := netio.TCPClientConfig{Name: "direct", Network: "tcp4", Dialer: conn.DefaultTCPDialer}
		tcpClient := tcpClientConfig.NewTCPClient()
		testResolver(t, "TCP", serverAddrPort, tcpClient, nil, logger)
		if err = <-errCh; err != nil {
			t.Fatal(err)
		}
	})
}

func TestResolverUDPStopsSenderBeforeClosingSession(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err = server.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}

	packer := &closeOrderPacker{
		server:      server.LocalAddr().(*net.UDPAddr).AddrPort(),
		secondQuery: make(chan []byte, 1),
		exited:      make(chan struct{}),
	}
	client := &closeOrderUDPClient{packer: packer}
	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 1232)
		n, peer, readErr := server.ReadFromUDPAddrPort(buf)
		if readErr != nil {
			errCh <- readErr
			return
		}
		q4 := bytes.Clone(buf[:n])
		q6 := <-packer.secondQuery
		for _, query := range [][]byte{q4, q6} {
			response, responseErr := testDNSResponse(query)
			if responseErr == nil {
				_, responseErr = server.WriteToUDPAddrPort(response, peer)
			}
			if responseErr != nil {
				errCh <- responseErr
				return
			}
		}
		errCh <- nil
	}()

	resolver := NewResolver("close-order", defaultCacheSize, packer.server, nil, client, zaptest.NewLogger(t))
	if _, err = resolver.Lookup(t.Context(), "example.com"); err != nil {
		t.Fatal(err)
	}
	if err = <-errCh; err != nil {
		t.Fatal(err)
	}
	if !client.closed {
		t.Fatal("UDP client session was not closed")
	}
	if client.closedBeforeSenderExit {
		t.Fatal("UDP client session was closed before the sender goroutine exited")
	}
}

func testDNSResponse(queryBytes []byte) ([]byte, error) {
	var query dnsmessage.Message
	if err := query.Unpack(queryBytes); err != nil {
		return nil, err
	}
	if len(query.Questions) != 1 {
		return nil, fmt.Errorf("got %d questions, want 1", len(query.Questions))
	}
	question := query.Questions[0]
	header := dnsmessage.ResourceHeader{Name: question.Name, Type: question.Type, Class: dnsmessage.ClassINET, TTL: 60}
	var answer dnsmessage.Resource
	switch question.Type {
	case dnsmessage.TypeA:
		answer = dnsmessage.Resource{Header: header, Body: &dnsmessage.AResource{A: netip.MustParseAddr("192.0.2.1").As4()}}
	case dnsmessage.TypeAAAA:
		answer = dnsmessage.Resource{Header: header, Body: &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:db8::1").As16()}}
	default:
		return nil, fmt.Errorf("unexpected question type %v", question.Type)
	}
	response := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: query.Header.ID, Response: true, RecursionAvailable: true},
		Questions: query.Questions,
		Answers:   []dnsmessage.Resource{answer},
	}
	return response.Pack()
}

func testResultBuilder(t *testing.T) (*resultBuilder, dnsmessage.Question) {
	t.Helper()
	name := dnsmessage.MustNewName("example.com.")
	question := dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	return &resultBuilder{
		q4: dnsQuery{id: 100, question: question},
		q6: dnsQuery{
			id:       200,
			question: dnsmessage.Question{Name: name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET},
			ipv6:     true,
		},
	}, question
}

func TestResultBuilderRejectsMismatchedQuestion(t *testing.T) {
	_, expected := testResultBuilder(t)
	cases := map[string]dnsmessage.Question{
		"Name":  {Name: dnsmessage.MustNewName("other.example."), Type: expected.Type, Class: expected.Class},
		"Type":  {Name: expected.Name, Type: dnsmessage.TypeAAAA, Class: expected.Class},
		"Class": {Name: expected.Name, Type: expected.Type, Class: dnsmessage.ClassCHAOS},
	}
	for name, question := range cases {
		t.Run(name, func(t *testing.T) {
			builder, _ := testResultBuilder(t)
			message := dnsmessage.Message{
				Header:    dnsmessage.Header{ID: 100, Response: true, RecursionAvailable: true},
				Questions: []dnsmessage.Question{question},
			}
			packet, err := message.Pack()
			if err != nil {
				t.Fatal(err)
			}
			if _, err = builder.parseMsg(packet, true); err == nil {
				t.Fatal("accepted a response for a different question")
			}
		})
	}
}

func TestResultBuilderRejectsUnrelatedAddressAnswer(t *testing.T) {
	other := dnsmessage.MustNewName("attacker.example.")
	builder, question4 := testResultBuilder(t)
	cases := []struct {
		name     string
		id       uint16
		question dnsmessage.Question
		answer   dnsmessage.Resource
	}{
		{
			name:     "A",
			id:       100,
			question: question4,
			answer: dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{Name: other, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
				Body:   &dnsmessage.AResource{A: netip.MustParseAddr("192.0.2.9").As4()},
			},
		},
		{
			name:     "AAAA",
			id:       200,
			question: builder.q6.question,
			answer: dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{Name: other, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 60},
				Body:   &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:db8::9").As16()},
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			builder, _ := testResultBuilder(t)
			message := dnsmessage.Message{
				Header:    dnsmessage.Header{ID: testCase.id, Response: true, RecursionAvailable: true},
				Questions: []dnsmessage.Question{testCase.question},
				Answers:   []dnsmessage.Resource{testCase.answer},
			}
			packet, err := message.Pack()
			if err != nil {
				t.Fatal(err)
			}
			if _, err = builder.parseMsg(packet, true); err == nil {
				t.Fatal("accepted an address answer unrelated to the queried name")
			}
			if len(builder.a) != 0 || len(builder.aaaa) != 0 {
				t.Fatalf("unrelated answer entered result: A=%v AAAA=%v", builder.a, builder.aaaa)
			}
		})
	}
}

func TestResultBuilderRejectsAddressAnswerWithWrongClass(t *testing.T) {
	builder, question := testResultBuilder(t)
	message := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 100, Response: true, RecursionAvailable: true},
		Questions: []dnsmessage.Question{question},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassCHAOS, TTL: 60},
			Body:   &dnsmessage.AResource{A: netip.MustParseAddr("192.0.2.9").As4()},
		}},
	}
	packet, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = builder.parseMsg(packet, true); err == nil {
		t.Fatal("accepted an address answer with the wrong class")
	}
}

func TestResultBuilderAcceptsAddressOwnedThroughCNAME(t *testing.T) {
	builder, question := testResultBuilder(t)
	alias := dnsmessage.MustNewName("alias.example.com.")
	want := netip.MustParseAddr("192.0.2.10")
	message := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 100, Response: true, RecursionAvailable: true},
		Questions: []dnsmessage.Question{question},
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 120},
				Body:   &dnsmessage.CNAMEResource{CNAME: alias},
			},
			{
				Header: dnsmessage.ResourceHeader{Name: alias, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
				Body:   &dnsmessage.AResource{A: want.As4()},
			},
		},
	}
	packet, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = builder.parseMsg(packet, true); err != nil {
		t.Fatal(err)
	}
	if len(builder.a) != 1 || builder.a[0] != want {
		t.Fatalf("addresses = %v, want [%v]", builder.a, want)
	}
}

func TestResolverTCPBoundedRetry(t *testing.T) {
	ctx := t.Context()
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	psc, ch := netiotest.NewPipeStreamClient(netio.StreamDialerInfo{
		Name:                 "test",
		NativeInitialPayload: true,
	})

	serverAddrPort := netip.AddrPortFrom(netip.IPv6Loopback(), 53)
	expectedServerAddr := conn.AddrFromIPPort(serverAddrPort)

	go func() {
		defer psc.Close()

		b := make([]byte, 2+512)

		for range 2 {
			select {
			case <-ctx.Done():
				t.Error("DialStream not called")
				return

			case pc := <-ch:
				if !pc.LocalConnAddr().Equals(expectedServerAddr) {
					t.Errorf("pc.LocalConnAddr() = %v, want %v", pc.LocalConnAddr(), expectedServerAddr)
				}

				if _, err := pc.Read(b); err != nil {
					t.Errorf("pc.Read failed: %v", err)
				}

				// After reading the query, close the connection without sending a response.
				_ = pc.Close()
			}
		}
	}()

	r := NewResolver("test", defaultCacheSize, serverAddrPort, psc, nil, logger)

	if _, err := r.Lookup(ctx, "example.com"); err == nil {
		t.Error("r.Lookup should have failed")
	}

	// This also synchronizes the exit of the server goroutine.
	if _, ok := <-ch; ok {
		t.Error("DialStream called more than expected")
	}
}
