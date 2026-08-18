package panel

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/database64128/shadowsocks-go/service"
	"golang.org/x/time/rate"
)

func TestReplaceTrafficLimitsPreservesUnchangedBuckets(t *testing.T) {
	runtime := NewRuntime(NewState())
	users := []User{{ID: 7, NodeSpeedLimit: 12}, {ID: 8}}
	if limited := runtime.ReplaceTrafficLimits(100, users); limited != 1 {
		t.Fatalf("limited users = %d, want 1", limited)
	}
	first := runtime.trafficLimits.Load()

	runtime.ReplaceTrafficLimits(100, users)
	second := runtime.trafficLimits.Load()
	if second.node != first.node {
		t.Fatal("unchanged node limiter was replaced")
	}
	if second.users[7] != first.users[7] {
		t.Fatal("unchanged user limiter was replaced")
	}

	runtime.ReplaceTrafficLimits(80, []User{{ID: 7, NodeSpeedLimit: 10}})
	third := runtime.trafficLimits.Load()
	if third.node == second.node {
		t.Fatal("changed node limiter was retained")
	}
	if third.users[7] == second.users[7] {
		t.Fatal("changed user limiter was retained")
	}
}

func TestRuntimeTrafficLimitZeroMeansUnlimited(t *testing.T) {
	runtime := NewRuntime(NewState())
	runtime.ReplaceTrafficLimits(0, []User{{ID: 7}})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := runtime.WaitTraffic(ctx, "tcp", "7", service.RuntimeTrafficUplink, 1<<20); err != nil {
		t.Fatalf("unlimited traffic waited on canceled context: %v", err)
	}
}

func TestRuntimeTrafficDirectionsHaveIndependentBuckets(t *testing.T) {
	runtime := NewRuntime(NewState())
	runtime.ReplaceTrafficLimits(0, []User{{ID: 7, NodeSpeedLimit: 0.016384}}) // 2048 bytes/s.

	if err := runtime.WaitTraffic(t.Context(), "tcp", "7", service.RuntimeTrafficUplink, minimumLimiterBurst); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := runtime.WaitTraffic(canceled, "udp", "7", service.RuntimeTrafficUplink, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("depleted uplink returned %v, want context cancellation", err)
	}
	if err := runtime.WaitTraffic(t.Context(), "udp", "7", service.RuntimeTrafficDownlink, minimumLimiterBurst); err != nil {
		t.Fatalf("uplink consumed downlink capacity: %v", err)
	}
}

func TestWaitRateLimitersUsesStricterSharedLimit(t *testing.T) {
	fast := rate.NewLimiter(1_000_000, 10)
	slow := rate.NewLimiter(1_000, 10)
	if err := waitRateLimiters(t.Context(), []*rate.Limiter{fast, slow}, 10); err != nil {
		t.Fatal(err)
	}
	startedAt := time.Now()
	if err := waitRateLimiters(t.Context(), []*rate.Limiter{fast, slow}, 10); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(startedAt); elapsed < 7*time.Millisecond {
		t.Fatalf("combined limiter waited only %s", elapsed)
	}
}

func TestTrafficLimitHotUpdateIsConcurrentSafe(t *testing.T) {
	runtime := NewRuntime(NewState())
	users := []User{{ID: 7, NodeSpeedLimit: 10_000}}
	runtime.ReplaceTrafficLimits(10_000, users)

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 200 {
				if err := runtime.WaitTraffic(t.Context(), "tcp", "7", service.RuntimeTrafficUplink, 1); err != nil {
					t.Errorf("wait traffic: %v", err)
					return
				}
			}
		})
	}
	for range 200 {
		runtime.ReplaceTrafficLimits(0, users)
		runtime.ReplaceTrafficLimits(10_000, users)
	}
	wg.Wait()
}
