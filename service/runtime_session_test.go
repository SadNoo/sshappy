package service

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testRuntimeSession struct {
	ctx     context.Context
	cancel  context.CancelFunc
	reserve func(RuntimeTrafficDirection, uint64, uint64) RuntimeTrafficReservation
}

func newTestRuntimeSession() *testRuntimeSession {
	ctx, cancel := context.WithCancel(context.Background())
	return &testRuntimeSession{ctx: ctx, cancel: cancel}
}

func (*testRuntimeSession) Identity() SessionIdentity  { return SessionIdentity{} }
func (s *testRuntimeSession) Context() context.Context { return s.ctx }
func (s *testRuntimeSession) Active() bool             { return s.ctx.Err() == nil }
func (*testRuntimeSession) Observe(netip.AddrPort)     {}
func (s *testRuntimeSession) ReserveTraffic(direction RuntimeTrafficDirection, packets, bytes uint64) RuntimeTrafficReservation {
	if s.reserve == nil {
		return nil
	}
	return s.reserve(direction, packets, bytes)
}
func (s *testRuntimeSession) Close() { s.cancel() }

type testRuntimeReservation struct {
	bytes     uint64
	committed atomic.Uint64
	refunded  atomic.Bool
	once      sync.Once
}

func (r *testRuntimeReservation) Bytes() uint64 { return r.bytes }
func (r *testRuntimeReservation) Commit(bytes uint64) {
	r.once.Do(func() { r.committed.Store(bytes) })
}
func (r *testRuntimeReservation) Refund() {
	r.once.Do(func() { r.refunded.Store(true) })
}

type testRuntimeConn struct {
	writeN   int
	writeErr error
	closed   chan struct{}
	close    sync.Once
}

func newTestRuntimeConn() *testRuntimeConn {
	return &testRuntimeConn{writeN: -1, closed: make(chan struct{})}
}

func (*testRuntimeConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *testRuntimeConn) Write(p []byte) (int, error) {
	if c.writeN < 0 || c.writeN > len(p) {
		return len(p), c.writeErr
	}
	return c.writeN, c.writeErr
}
func (c *testRuntimeConn) Close() error {
	c.close.Do(func() { close(c.closed) })
	return nil
}
func (*testRuntimeConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*testRuntimeConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*testRuntimeConn) SetDeadline(time.Time) error      { return nil }
func (*testRuntimeConn) SetReadDeadline(time.Time) error  { return nil }
func (*testRuntimeConn) SetWriteDeadline(time.Time) error { return nil }
func (*testRuntimeConn) CloseWrite() error                { return nil }

func TestRuntimeInvalidationClosesLiveConnection(t *testing.T) {
	t.Parallel()
	session := newTestRuntimeSession()
	connection := newTestRuntimeConn()
	stop := closeConnectionsOnRuntimeEnd(session, connection)
	defer stop()
	session.cancel()
	select {
	case <-connection.closed:
	case <-time.After(time.Second):
		t.Fatal("runtime invalidation did not close the live connection")
	}
}

func TestReserveFullRuntimeTrafficRefundsPartialReservation(t *testing.T) {
	t.Parallel()
	session := newTestRuntimeSession()
	reservation := &testRuntimeReservation{bytes: 3}
	session.reserve = func(RuntimeTrafficDirection, uint64, uint64) RuntimeTrafficReservation {
		return reservation
	}
	actual, ok := reserveFullRuntimeTraffic(session, RuntimeTrafficUplink, 1, 5)
	if ok || actual != nil || !reservation.refunded.Load() {
		t.Fatalf("partial reservation = %#v, accepted=%v, refunded=%v", actual, ok, reservation.refunded.Load())
	}
}

func TestMeteredTCPConnCommitsOnlyConfirmedPrefix(t *testing.T) {
	t.Parallel()
	session := newTestRuntimeSession()
	reservation := &testRuntimeReservation{bytes: 5}
	session.reserve = func(RuntimeTrafficDirection, uint64, uint64) RuntimeTrafficReservation {
		return reservation
	}
	connection := newTestRuntimeConn()
	connection.writeN = 3
	var written atomic.Uint64
	metered := &meteredTCPConn{
		Conn: connection, written: &written, session: session, direction: RuntimeTrafficUplink,
	}
	n, err := metered.Write([]byte("hello"))
	if n != 3 || !errors.Is(err, io.ErrShortWrite) || reservation.committed.Load() != 3 || written.Load() != 3 {
		t.Fatalf("Write() = %d, %v; committed=%d written=%d", n, err, reservation.committed.Load(), written.Load())
	}
}

func TestMeteredTCPConnRefundsFailedWrite(t *testing.T) {
	t.Parallel()
	session := newTestRuntimeSession()
	reservation := &testRuntimeReservation{bytes: 5}
	session.reserve = func(RuntimeTrafficDirection, uint64, uint64) RuntimeTrafficReservation {
		return reservation
	}
	connection := newTestRuntimeConn()
	connection.writeN = 0
	connection.writeErr = errors.New("write failed")
	var written atomic.Uint64
	metered := &meteredTCPConn{
		Conn: connection, written: &written, session: session, direction: RuntimeTrafficDownlink,
	}
	if n, err := metered.Write([]byte("hello")); n != 0 || err == nil || !reservation.refunded.Load() {
		t.Fatalf("Write() = %d, %v; refunded=%v", n, err, reservation.refunded.Load())
	}
}

func TestMeteredTCPConnEmptyWriteIsNoOp(t *testing.T) {
	t.Parallel()
	session := newTestRuntimeSession()
	session.reserve = func(RuntimeTrafficDirection, uint64, uint64) RuntimeTrafficReservation {
		t.Fatal("empty write attempted a quota reservation")
		return nil
	}
	connection := newTestRuntimeConn()
	var written atomic.Uint64
	metered := &meteredTCPConn{
		Conn: connection, written: &written, session: session, direction: RuntimeTrafficUplink,
	}
	if n, err := metered.Write(nil); n != 0 || err != nil || written.Load() != 0 {
		t.Fatalf("empty Write() = %d, %v; written=%d", n, err, written.Load())
	}
}

func TestSettleRuntimeTrafficBatchResultHandlesPartialAndFailedEntries(t *testing.T) {
	t.Parallel()
	reservations := []*testRuntimeReservation{{bytes: 2}, {bytes: 3}, {bytes: 5}}
	interfaces := make([]RuntimeTrafficReservation, len(reservations))
	for index := range reservations {
		interfaces[index] = reservations[index]
	}
	sentPackets, sentBytes, advance := settleRuntimeTrafficBatchResult(
		interfaces, []uint64{2, 3, 5}, 1, true,
	)
	if sentPackets != 1 || sentBytes != 2 || advance != 2 {
		t.Fatalf("batch result = packets %d bytes %d advance %d", sentPackets, sentBytes, advance)
	}
	if reservations[0].committed.Load() != 2 || !reservations[1].refunded.Load() ||
		reservations[2].committed.Load() != 0 || reservations[2].refunded.Load() {
		t.Fatalf("partial batch reservations = %+v", reservations)
	}

	// A short result without an error advances only over the confirmed prefix;
	// the untouched suffix remains available for the caller's next syscall.
	last := &testRuntimeReservation{bytes: 5}
	sentPackets, sentBytes, advance = settleRuntimeTrafficBatchResult(
		[]RuntimeTrafficReservation{last}, []uint64{5}, 0, false,
	)
	if sentPackets != 0 || sentBytes != 0 || advance != 0 || last.refunded.Load() || last.committed.Load() != 0 {
		t.Fatalf("no-error short batch was settled: packets=%d bytes=%d advance=%d reservation=%+v",
			sentPackets, sentBytes, advance, last)
	}
}
