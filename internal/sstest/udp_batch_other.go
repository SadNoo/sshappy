//go:build !linux

package sstest

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/database64128/shadowsocks-go/zerocopy"
)

type udpSessionBatch struct{}

func configureUDPSessionBatch(*udpSession) error {
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

func udpSocketBufferSizes(*net.UDPConn) (readBuffer, writeBuffer int, err error) {
	return 0, 0, fmt.Errorf("UDP socket buffer inspection is unsupported")
}
