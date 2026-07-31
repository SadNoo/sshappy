package panel

import (
	"fmt"
	"sync"
	"time"
)

type failClosedFailure struct {
	operation string
	since     time.Time
	err       error
}

// failClosedWindow tracks independent refresh/reporting failures under one
// fail-closed deadline. Its timer callback invokes onExpire directly, so the
// relay is canceled at the deadline even if the runner is blocked in a database
// operation and cannot immediately return to its select loop.
type failClosedWindow struct {
	mu         sync.Mutex
	grace      time.Duration
	failures   map[string]failClosedFailure
	timer      *time.Timer
	generation uint64
	expired    *failClosedFailure
	expiredC   chan struct{}
	onExpire   func()
}

func newFailClosedWindow(grace time.Duration, onExpire func()) *failClosedWindow {
	return &failClosedWindow{
		grace:    grace,
		failures: make(map[string]failClosedFailure),
		expiredC: make(chan struct{}, 1),
		onExpire: onExpire,
	}
}

func (w *failClosedWindow) RecordFailure(operation string, err error, now time.Time) (age, remaining time.Duration, expired bool) {
	w.mu.Lock()
	if w.expired != nil {
		failure := *w.expired
		w.mu.Unlock()
		return max(now.Sub(failure.since), 0), 0, true
	}
	failure, ok := w.failures[operation]
	if !ok {
		failure = failClosedFailure{operation: operation, since: now}
	}
	failure.err = err
	w.failures[operation] = failure
	age = max(now.Sub(failure.since), 0)
	remaining = max(w.grace-age, 0)
	if remaining == 0 {
		w.expireLocked(failure)
		expired = true
		w.mu.Unlock()
		w.fireExpiration()
		return
	}
	w.scheduleLocked(now)
	w.mu.Unlock()
	return
}

func (w *failClosedWindow) RecordSuccess(operation string, now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.expired != nil {
		return
	}
	if _, ok := w.failures[operation]; !ok {
		return
	}
	delete(w.failures, operation)
	w.scheduleLocked(now)
}

func (w *failClosedWindow) Expired() <-chan struct{} {
	return w.expiredC
}

func (w *failClosedWindow) Err(now time.Time) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.expired == nil {
		return nil
	}
	age := max(now.Sub(w.expired.since), 0)
	return fmt.Errorf("%s remained stale for %s: %w", w.expired.operation, age, w.expired.err)
}

func (w *failClosedWindow) Close() {
	w.mu.Lock()
	w.generation++
	if w.timer != nil {
		w.timer.Stop()
		w.timer = nil
	}
	w.mu.Unlock()
}

func (w *failClosedWindow) scheduleLocked(now time.Time) {
	w.generation++
	if w.timer != nil {
		w.timer.Stop()
		w.timer = nil
	}
	if len(w.failures) == 0 {
		return
	}
	failure := w.earliestLocked()
	delay := max(failure.since.Add(w.grace).Sub(now), 0)
	generation := w.generation
	w.timer = time.AfterFunc(delay, func() {
		w.expireGeneration(generation)
	})
}

func (w *failClosedWindow) expireGeneration(generation uint64) {
	w.mu.Lock()
	if generation != w.generation || w.expired != nil || len(w.failures) == 0 {
		w.mu.Unlock()
		return
	}
	failure := w.earliestLocked()
	remaining := failure.since.Add(w.grace).Sub(time.Now())
	if remaining > 0 {
		w.scheduleLocked(time.Now())
		w.mu.Unlock()
		return
	}
	w.expireLocked(failure)
	w.mu.Unlock()
	w.fireExpiration()
}

func (w *failClosedWindow) expireLocked(failure failClosedFailure) {
	w.generation++
	if w.timer != nil {
		w.timer.Stop()
		w.timer = nil
	}
	w.expired = &failure
}

func (w *failClosedWindow) fireExpiration() {
	if w.onExpire != nil {
		w.onExpire()
	}
	select {
	case w.expiredC <- struct{}{}:
	default:
	}
}

func (w *failClosedWindow) earliestLocked() failClosedFailure {
	var earliest failClosedFailure
	for _, failure := range w.failures {
		if earliest.since.IsZero() || failure.since.Before(earliest.since) {
			earliest = failure
		}
	}
	return earliest
}
