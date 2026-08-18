package service

import (
	"context"
	"testing"
)

type trafficLimiterTestObserver struct {
	basicTargetTestObserver
	network   string
	username  string
	direction RuntimeTrafficDirection
	bytes     int
}

func (o *trafficLimiterTestObserver) WaitTraffic(_ context.Context, network, username string, direction RuntimeTrafficDirection, bytes int) error {
	o.network = network
	o.username = username
	o.direction = direction
	o.bytes = bytes
	return nil
}

func TestWaitRuntimeTrafficIsOptional(t *testing.T) {
	if err := waitRuntimeTraffic(t.Context(), basicTargetTestObserver{}, "tcp", "7", RuntimeTrafficUplink, 100); err != nil {
		t.Fatal(err)
	}

	observer := &trafficLimiterTestObserver{}
	if err := waitRuntimeTraffic(t.Context(), observer, "udp", "8", RuntimeTrafficDownlink, 321); err != nil {
		t.Fatal(err)
	}
	if observer.network != "udp" || observer.username != "8" || observer.direction != RuntimeTrafficDownlink || observer.bytes != 321 {
		t.Fatalf("unexpected limiter call: %+v", observer)
	}
}

var _ RuntimeObserver = (*trafficLimiterTestObserver)(nil)
var _ RuntimeTrafficLimiter = (*trafficLimiterTestObserver)(nil)
