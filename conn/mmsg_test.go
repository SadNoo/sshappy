//go:build linux || netbsd

package conn

import (
	"syscall"
	"testing"
)

func TestMmsgWConnWriteMsgsEmpty(t *testing.T) {
	wc := &MmsgWConn{}
	if n, err := wc.WriteMsgs(nil, 0); n != 0 || err != nil {
		t.Fatalf("WriteMsgs(nil) = (%d, %v), want (0, nil)", n, err)
	}
}

func TestMmsgWConnWriteRetainsProgressAcrossReadinessCallbacks(t *testing.T) {
	wc := &MmsgWConn{writeMsgvec: make([]Mmsghdr, 3)}
	firstCalls := 0
	firstDone := wc.write(1, func(_ int, msgvec []Mmsghdr, _ int) (int, syscall.Errno) {
		firstCalls++
		switch firstCalls {
		case 1:
			if len(msgvec) != 3 {
				t.Fatalf("first msgvec length = %d, want 3", len(msgvec))
			}
			return 1, 0
		case 2:
			if len(msgvec) != 2 {
				t.Fatalf("second msgvec length = %d, want 2", len(msgvec))
			}
			return 0, syscall.EAGAIN
		default:
			t.Fatalf("unexpected first-callback call %d", firstCalls)
			return 0, syscall.EIO
		}
	})
	if firstDone {
		t.Fatal("first readiness callback reported completion")
	}
	if wc.writeN != 1 || len(wc.writeMsgvec) != 2 {
		t.Fatalf("progress after first callback = (%d, %d remaining), want (1, 2)", wc.writeN, len(wc.writeMsgvec))
	}

	secondDone := wc.write(1, func(_ int, msgvec []Mmsghdr, _ int) (int, syscall.Errno) {
		return len(msgvec), 0
	})
	if !secondDone {
		t.Fatal("second readiness callback did not report completion")
	}
	if wc.writeErr != nil {
		t.Fatalf("write error = %v, want nil", wc.writeErr)
	}
	if wc.writeN != 3 || len(wc.writeMsgvec) != 0 {
		t.Fatalf("final progress = (%d, %d remaining), want (3, 0)", wc.writeN, len(wc.writeMsgvec))
	}
}
