package panel

import (
	"context"
	"strconv"
	"time"

	"github.com/database64128/shadowsocks-go/service"
	"golang.org/x/time/rate"
)

const (
	bytesPerMegabit     = 1_000_000.0 / 8.0
	minimumLimiterBurst = 2 * 1024
	maximumLimiterBurst = 256 * 1024
	limiterBurstTime    = 100 * time.Millisecond
)

type directionalTrafficLimiter struct {
	mbps     float64
	uplink   *rate.Limiter
	downlink *rate.Limiter
}

type trafficLimitSet struct {
	node  *directionalTrafficLimiter
	users map[int]*directionalTrafficLimiter
}

func newDirectionalTrafficLimiter(mbps float64) *directionalTrafficLimiter {
	bytesPerSecond := mbps * bytesPerMegabit
	burst := int(bytesPerSecond * limiterBurstTime.Seconds())
	burst = max(burst, minimumLimiterBurst)
	burst = min(burst, maximumLimiterBurst)
	limit := rate.Limit(bytesPerSecond)
	return &directionalTrafficLimiter{
		mbps:     mbps,
		uplink:   rate.NewLimiter(limit, burst),
		downlink: rate.NewLimiter(limit, burst),
	}
}

func reuseOrCreateTrafficLimiter(previous *directionalTrafficLimiter, mbps float64) *directionalTrafficLimiter {
	if mbps == 0 {
		return nil
	}
	if previous != nil && previous.mbps == mbps {
		return previous
	}
	return newDirectionalTrafficLimiter(mbps)
}

// ReplaceTrafficLimits atomically publishes the limits read from the existing
// panel fields. Unchanged limiters are retained so periodic synchronization
// cannot reset their token buckets.
func (r *Runtime) ReplaceTrafficLimits(nodeMbps float64, users []User) int {
	previous := r.trafficLimits.Load()
	if previous == nil {
		previous = &trafficLimitSet{users: make(map[int]*directionalTrafficLimiter)}
	}

	next := &trafficLimitSet{
		node:  reuseOrCreateTrafficLimiter(previous.node, nodeMbps),
		users: make(map[int]*directionalTrafficLimiter),
	}
	for _, user := range users {
		if user.NodeSpeedLimit == 0 {
			continue
		}
		next.users[user.ID] = reuseOrCreateTrafficLimiter(previous.users[user.ID], user.NodeSpeedLimit)
	}
	r.trafficLimits.Store(next)
	return len(next.users)
}

// WaitTraffic implements service.RuntimeTrafficLimiter. Node and user limits
// are reserved for the same interval, so the stricter limit wins without
// serially charging the same bytes twice.
func (r *Runtime) WaitTraffic(ctx context.Context, _ string, username string, direction service.RuntimeTrafficDirection, bytes int) error {
	if bytes <= 0 {
		return nil
	}
	limits := r.trafficLimits.Load()
	if limits == nil {
		return nil
	}

	userID, err := strconv.Atoi(username)
	if err != nil {
		return nil
	}
	user := limits.users[userID]
	limiters := make([]*rate.Limiter, 0, 2)
	if node := limiterForDirection(limits.node, direction); node != nil {
		limiters = append(limiters, node)
	}
	if userLimiter := limiterForDirection(user, direction); userLimiter != nil {
		limiters = append(limiters, userLimiter)
	}
	return waitRateLimiters(ctx, limiters, bytes)
}

func limiterForDirection(limiter *directionalTrafficLimiter, direction service.RuntimeTrafficDirection) *rate.Limiter {
	if limiter == nil {
		return nil
	}
	if direction == service.RuntimeTrafficDownlink {
		return limiter.downlink
	}
	return limiter.uplink
}

func waitRateLimiters(ctx context.Context, limiters []*rate.Limiter, bytes int) error {
	if len(limiters) == 0 || bytes <= 0 {
		return nil
	}

	maxChunk := bytes
	for _, limiter := range limiters {
		maxChunk = min(maxChunk, limiter.Burst())
	}
	for remaining := bytes; remaining > 0; {
		chunk := min(remaining, maxChunk)
		now := time.Now()
		reservations := make([]*rate.Reservation, len(limiters))
		var delay time.Duration
		for i, limiter := range limiters {
			reservation := limiter.ReserveN(now, chunk)
			reservations[i] = reservation
			if reservationDelay := reservation.DelayFrom(now); reservationDelay > delay {
				delay = reservationDelay
			}
		}

		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				canceledAt := time.Now()
				for _, reservation := range reservations {
					reservation.CancelAt(canceledAt)
				}
				return ctx.Err()
			case <-timer.C:
			}
		} else if err := ctx.Err(); err != nil {
			canceledAt := time.Now()
			for _, reservation := range reservations {
				reservation.CancelAt(canceledAt)
			}
			return err
		}
		remaining -= chunk
	}
	return nil
}

var _ service.RuntimeTrafficLimiter = (*Runtime)(nil)
