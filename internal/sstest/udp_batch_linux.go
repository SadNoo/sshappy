//go:build linux

package sstest

import (
	"context"
	"errors"
	"log"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"time"
	"unsafe"

	ssconn "github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"golang.org/x/sys/unix"
)

const udpControlBufferSize = 32

type udpSessionBatch struct {
	outboundReader *ssconn.MmsgRConn
	outboundWriter *ssconn.MmsgWConn
	inboundWriter  *ssconn.MmsgWConn
}

func configureUDPSessionBatch(session *udpSession) error {
	outboundRaw, err := ssconn.NewRawUDPConn(session.outbound)
	if err != nil {
		return err
	}
	inboundRaw, err := ssconn.NewRawUDPConn(session.inbound)
	if err != nil {
		return err
	}
	if err := enableUDPOverflow(session.outbound); err != nil {
		log.Printf("debug: UDP target overflow tracking setup failed: %v", err)
	}
	session.batch = udpSessionBatch{
		outboundReader: outboundRaw.RConn(),
		outboundWriter: outboundRaw.WConn(),
		inboundWriter:  inboundRaw.WConn(),
	}
	return nil
}

func (r *udpRuntime) serve(inbound *net.UDPConn) {
	raw, err := ssconn.NewRawUDPConn(inbound)
	if err != nil {
		log.Printf("UDP listener batch setup failed: %v", err)
		return
	}
	if err := enableUDPOverflow(inbound); err != nil {
		log.Printf("debug: UDP listener overflow tracking setup failed: %v", err)
	}
	reader := raw.RConn()
	batchSize := r.config.UDPServerBatchSize
	if batchSize <= 0 {
		batchSize = 64
	}

	packets := make([]*udpQueuedPacket, batchSize)
	names := make([]unix.RawSockaddrInet6, batchSize)
	iovecs := make([]unix.Iovec, batchSize)
	controls := make([][udpControlBufferSize]byte, batchSize)
	messages := make([]ssconn.Mmsghdr, batchSize)
	for i := range messages {
		messages[i].Msghdr.Name = (*byte)(unsafe.Pointer(&names[i]))
		messages[i].Msghdr.Iov = &iovecs[i]
		messages[i].Msghdr.SetIovlen(1)
		messages[i].Msghdr.Control = &controls[i][0]
	}

	var overflow udpOverflowCounter
	for {
		for i := range messages {
			queued := r.getPacket()
			packets[i] = queued
			iovecs[i].Base = &queued.buf[udpPacketHeadroom]
			iovecs[i].SetLen(len(queued.buf) - udpPacketHeadroom - 32)
			messages[i].Msghdr.Namelen = unix.SizeofSockaddrInet6
			messages[i].Msghdr.SetControllen(udpControlBufferSize)
			messages[i].Msghdr.Flags = 0
			messages[i].Msglen = 0
		}

		count, err := reader.ReadMsgs(messages, 0)
		if err != nil {
			for _, queued := range packets {
				r.putPacket(queued)
			}
			if !isExpectedCloseError(err) {
				log.Printf("debug: UDP listener batch read failed: %v", err)
			}
			return
		}
		r.metrics.serverRecvCalls.Add(1)
		updateAtomicMax(&r.metrics.serverRecvMax, uint64(count))

		for i := 0; i < count; i++ {
			message := &messages[i]
			queued := packets[i]
			accountUDPOverflow(
				controls[i][:message.Msghdr.Controllen],
				&overflow,
				&r.metrics.kernelDropIn,
			)
			clientAddr, err := ssconn.SockaddrToAddrPort(message.Msghdr.Name, message.Msghdr.Namelen)
			if err != nil || ssconn.ParseFlagsForError(int(message.Msghdr.Flags)) != nil {
				r.metrics.dropDecrypt.Add(1)
				r.putPacket(queued)
				continue
			}
			packetLen := int(message.Msglen)
			r.metrics.rxPackets.Add(1)
			r.metrics.rxBytes.Add(uint64(packetLen))
			if !r.dispatch(inbound, queued, clientAddr, packetLen) {
				r.putPacket(queued)
			}
		}
		for i := count; i < batchSize; i++ {
			r.putPacket(packets[i])
		}
	}
}

func (r *udpRuntime) relayUplink(session *udpSession) {
	batchSize := r.config.UDPRelayBatchSize
	if batchSize <= 0 {
		batchSize = 8
	}
	resolved := make(map[string]netip.AddrPort)
	packets := make([]*udpQueuedPacket, batchSize)
	names := make([]unix.RawSockaddrInet6, batchSize)
	iovecs := make([]unix.Iovec, batchSize)
	messages := make([]ssconn.Mmsghdr, batchSize)
	for i := range messages {
		messages[i].Msghdr.Name = (*byte)(unsafe.Pointer(&names[i]))
		messages[i].Msghdr.Iov = &iovecs[i]
		messages[i].Msghdr.SetIovlen(1)
	}
	defer r.drainUDPSessionQueue(session)

	for {
		var first *udpQueuedPacket
		select {
		case <-session.done:
			return
		case first = <-session.send:
		}

		count := 0
		queued := first
		for queued != nil {
			targetKey := queued.target.String()
			targetAddr, ok := resolved[targetKey]
			if !ok {
				ctx, cancel := context.WithTimeout(
					context.Background(),
					time.Duration(r.config.TCPConnectTimeout)*time.Second,
				)
				var resolveErr error
				targetAddr, resolveErr = queued.target.ResolveIPPort(ctx, "ip")
				cancel()
				if resolveErr != nil {
					r.metrics.dropResolve.Add(1)
					r.putPacket(queued)
					queued = r.tryDequeueUDPPacket(session)
					continue
				}
				resolved[targetKey] = targetAddr
			}
			name, nameLen := ssconn.AddrPortToSockaddrValue(targetAddr)
			packets[count] = queued
			names[count] = name
			messages[count].Msghdr.Namelen = nameLen
			iovecs[count].Base = &queued.buf[queued.start]
			iovecs[count].SetLen(queued.length)
			count++
			if count == batchSize {
				break
			}
			queued = r.tryDequeueUDPPacket(session)
		}
		if count == 0 {
			continue
		}

		err := session.batch.outboundWriter.WriteMsgs(messages[:count], 0)
		r.metrics.relaySendCalls.Add(1)
		updateAtomicMax(&r.metrics.relaySendMax, uint64(count))
		if err != nil {
			if !isExpectedCloseError(err) {
				r.metrics.dropTargetWrite.Add(1)
				log.Printf("debug: UDP target batch write failed: %v", err)
			}
		}
		for _, packet := range packets[:count] {
			session.upload.Add(int64(packet.length))
			r.putPacket(packet)
		}
		session.lastActive.Store(time.Now().UnixNano())
	}
}

func (r *udpRuntime) relayDownlink(session *udpSession) {
	defer r.closeSession(session)
	batchSize := r.config.UDPRelayBatchSize
	if batchSize <= 0 {
		batchSize = 8
	}

	receiveNames := make([]unix.RawSockaddrInet6, batchSize)
	sendNames := make([]unix.RawSockaddrInet6, batchSize)
	buffers := make([][]byte, batchSize)
	receiveIovecs := make([]unix.Iovec, batchSize)
	sendIovecs := make([]unix.Iovec, batchSize)
	controls := make([][udpControlBufferSize]byte, batchSize)
	receiveMessages := make([]ssconn.Mmsghdr, batchSize)
	sendMessages := make([]ssconn.Mmsghdr, batchSize)
	for i := range receiveMessages {
		buf := make([]byte, r.packetCapacity)
		buffers[i] = buf
		receiveIovecs[i].Base = &buf[udpPacketHeadroom]
		receiveIovecs[i].SetLen(len(buf) - udpPacketHeadroom - 32)
		receiveMessages[i].Msghdr.Name = (*byte)(unsafe.Pointer(&receiveNames[i]))
		receiveMessages[i].Msghdr.Namelen = unix.SizeofSockaddrInet6
		receiveMessages[i].Msghdr.Iov = &receiveIovecs[i]
		receiveMessages[i].Msghdr.SetIovlen(1)
		receiveMessages[i].Msghdr.Control = &controls[i][0]

		sendMessages[i].Msghdr.Name = (*byte)(unsafe.Pointer(&sendNames[i]))
		sendMessages[i].Msghdr.Iov = &sendIovecs[i]
		sendMessages[i].Msghdr.SetIovlen(1)
	}

	var overflow udpOverflowCounter
	for {
		for i := range receiveMessages {
			receiveMessages[i].Msghdr.Namelen = unix.SizeofSockaddrInet6
			receiveMessages[i].Msghdr.SetControllen(udpControlBufferSize)
			receiveMessages[i].Msghdr.Flags = 0
			receiveMessages[i].Msglen = 0
		}
		count, err := session.batch.outboundReader.ReadMsgs(receiveMessages, 0)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) && r.refreshActiveUDPSessionDeadline(session) {
				continue
			}
			if !errors.Is(err, os.ErrDeadlineExceeded) && !isExpectedCloseError(err) {
				log.Printf("debug: UDP target batch read failed: %v", err)
			}
			return
		}
		r.metrics.relayRecvCalls.Add(1)
		updateAtomicMax(&r.metrics.relayRecvMax, uint64(count))

		client := session.clientAddr.Load()
		if client == nil || !client.addr.IsValid() {
			continue
		}
		clientName, clientNameLen := ssconn.AddrPortToSockaddrValue(client.addr)
		maxPacketSize := zerocopy.MaxPacketSizeForAddr(r.udpMTU(), client.addr.Addr())
		sendCount := 0
		payloadBytes := 0
		for i := 0; i < count; i++ {
			message := &receiveMessages[i]
			accountUDPOverflow(
				controls[i][:message.Msghdr.Controllen],
				&overflow,
				&r.metrics.kernelDropOut,
			)
			sourceAddr, err := ssconn.SockaddrToAddrPort(message.Msghdr.Name, message.Msghdr.Namelen)
			if err != nil || ssconn.ParseFlagsForError(int(message.Msghdr.Flags)) != nil {
				r.metrics.dropPack.Add(1)
				continue
			}
			payloadLen := int(message.Msglen)
			packetStart, packetLen, err := session.packer.PackInPlace(
				buffers[i],
				sourceAddr,
				udpPacketHeadroom,
				payloadLen,
				maxPacketSize,
			)
			if err != nil {
				r.metrics.dropPack.Add(1)
				continue
			}
			sendNames[sendCount] = clientName
			sendMessages[sendCount].Msghdr.Namelen = clientNameLen
			sendIovecs[sendCount].Base = &buffers[i][packetStart]
			sendIovecs[sendCount].SetLen(packetLen)
			sendCount++
			payloadBytes += payloadLen
		}
		if sendCount == 0 {
			continue
		}
		err = session.batch.inboundWriter.WriteMsgs(sendMessages[:sendCount], 0)
		r.metrics.relaySendCalls.Add(1)
		updateAtomicMax(&r.metrics.relaySendMax, uint64(sendCount))
		if err != nil {
			if !isExpectedCloseError(err) {
				r.metrics.dropClientWrite.Add(1)
			}
		}
		r.metrics.txPackets.Add(uint64(sendCount))
		r.metrics.txBytes.Add(uint64(payloadBytes))
		session.download.Add(int64(payloadBytes))
	}
}

func (r *udpRuntime) refreshActiveUDPSessionDeadline(session *udpSession) bool {
	lastActive := time.Unix(0, session.lastActive.Load())
	deadline := lastActive.Add(r.idleTimeout())
	if !deadline.After(time.Now()) {
		return false
	}
	return session.outbound.SetReadDeadline(deadline) == nil
}

func (r *udpRuntime) tryDequeueUDPPacket(session *udpSession) *udpQueuedPacket {
	select {
	case <-session.done:
		return nil
	case queued := <-session.send:
		return queued
	default:
		return nil
	}
}

func (r *udpRuntime) drainUDPSessionQueue(session *udpSession) {
	for {
		select {
		case queued := <-session.send:
			r.putPacket(queued)
		default:
			return
		}
	}
}

type udpOverflowCounter struct {
	value uint32
	seen  bool
}

func accountUDPOverflow(control []byte, last *udpOverflowCounter, total *atomic.Uint64) {
	value, ok := parseUDPOverflow(control)
	if !ok {
		return
	}
	var delta uint32
	if last.seen {
		delta = value - last.value
	} else {
		delta = value
		last.seen = true
	}
	last.value = value
	total.Add(uint64(delta))
}

func parseUDPOverflow(control []byte) (uint32, bool) {
	headerSize := unix.CmsgLen(0)
	for len(control) >= headerSize {
		header := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
		messageLen := int(header.Len)
		if messageLen < headerSize || messageLen > len(control) {
			return 0, false
		}
		if header.Level == unix.SOL_SOCKET &&
			header.Type == unix.SO_RXQ_OVFL &&
			messageLen >= headerSize+4 {
			return *(*uint32)(unsafe.Pointer(&control[headerSize])), true
		}
		next := unix.CmsgSpace(messageLen - headerSize)
		if next <= 0 || next > len(control) {
			return 0, false
		}
		control = control[next:]
	}
	return 0, false
}

func enableUDPOverflow(conn *net.UDPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		socketErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RXQ_OVFL, 1)
	}); err != nil {
		return err
	}
	return socketErr
}

func udpSocketBufferSizes(conn *net.UDPConn) (readBuffer, writeBuffer int, err error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		readBuffer, socketErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
		if socketErr != nil {
			return
		}
		writeBuffer, socketErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF)
	}); err != nil {
		return 0, 0, err
	}
	return readBuffer, writeBuffer, socketErr
}
