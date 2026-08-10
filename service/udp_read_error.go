package service

import (
	"context"
	"errors"
	"net"
	"os"
	"time"
)

const (
	udpReadRetryInitialBackoff = 10 * time.Millisecond
	udpReadRetryMaxBackoff     = time.Second
)

// udpReadErrorBackoff classifies socket read failures and bounds retries.
// Closed, expired, canceled, and permanent failures terminate immediately.
// Only errors explicitly marked temporary may retry; a persistent failure is
// logged once and exponentially backed off to avoid CPU and log busy-loops.
type udpReadErrorBackoff struct {
	nextDelay time.Duration
	logged    bool
}

func (backoff *udpReadErrorBackoff) reset() {
	backoff.nextDelay = 0
	backoff.logged = false
}

func (backoff *udpReadErrorBackoff) shouldRetry(
	ctx context.Context,
	err error,
	logTemporaryOrPermanentError func(error),
) bool {
	if err == nil {
		backoff.reset()
		return true
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil || errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, net.ErrClosed) {
		return false
	}

	var netErr net.Error
	isNetworkError := errors.As(err, &netErr)
	if isNetworkError && netErr.Timeout() {
		return false
	}
	if !isNetworkError || !netErr.Temporary() {
		if logTemporaryOrPermanentError != nil {
			logTemporaryOrPermanentError(err)
		}
		return false
	}
	if !backoff.logged && logTemporaryOrPermanentError != nil {
		logTemporaryOrPermanentError(err)
		backoff.logged = true
	}

	delay := backoff.nextDelay
	if delay == 0 {
		delay = udpReadRetryInitialBackoff
	}
	timer := time.NewTimer(delay)
	select {
	case <-ctx.Done():
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		return false
	case <-timer.C:
	}
	backoff.nextDelay = min(delay*2, udpReadRetryMaxBackoff)
	return true
}
