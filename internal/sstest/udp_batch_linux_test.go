//go:build linux

package sstest

import (
	"sync/atomic"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestUDPOverflowControlMessage(t *testing.T) {
	control := makeUDPOverflowControlMessage(17)
	value, ok := parseUDPOverflow(control)
	if !ok || value != 17 {
		t.Fatalf("parseUDPOverflow() = %d, %v", value, ok)
	}

	var last udpOverflowCounter
	var total atomic.Uint64
	accountUDPOverflow(control, &last, &total)
	accountUDPOverflow(makeUDPOverflowControlMessage(23), &last, &total)
	if got := total.Load(); got != 23 {
		t.Fatalf("overflow total = %d, want 23", got)
	}
}

func makeUDPOverflowControlMessage(value uint32) []byte {
	control := make([]byte, unix.CmsgSpace(4))
	header := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
	header.SetLen(unix.CmsgLen(4))
	header.Level = unix.SOL_SOCKET
	header.Type = unix.SO_RXQ_OVFL
	*(*uint32)(unsafe.Pointer(&control[unix.CmsgLen(0)])) = value
	return control
}
