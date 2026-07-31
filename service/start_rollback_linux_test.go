//go:build linux

package service

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestUDPTransparentRelayStopCancelsSessionsBeforeWaiting(t *testing.T) {
	relay := &UDPTransparentRelay{
		logger: zap.NewNop(),
		table:  make(map[transparentNATKey]*transparentNATEntry),
	}
	runCtx := relay.lifecycle.start(context.Background())
	relay.wg.Go(func() {
		<-runCtx.Done()
	})

	done := make(chan error, 1)
	go func() {
		done <- relay.Stop()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(lifecycleTestTimeout):
		t.Fatal("Stop waited for a transparent session without cancelling its context")
	}
}
