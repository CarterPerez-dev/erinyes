// ©AngelaMos | 2026
// ratelimit.go

package gh

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"
)

var ErrRateLimited = errors.New("github rate limit exhausted and retries gave up")

const (
	SearchRequestsPerMinute = 10
	minSearchInterval       = time.Minute / SearchRequestsPerMinute
	secondaryBackoffBase    = 60 * time.Second
	transientBackoffBase    = 2 * time.Second
	rateLimitFloor          = 5
)

type Limiter struct {
	mu       sync.Mutex
	interval time.Duration
	last     time.Time
}

func NewLimiter(rps float64) *Limiter {
	interval := time.Duration(0)
	if rps > 0 {
		interval = time.Duration(float64(time.Second) / rps)
	}
	return &Limiter{interval: interval}
}

func (l *Limiter) SetMinInterval(d time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if d > l.interval {
		l.interval = d
	}
}

func (l *Limiter) Wait(ctx context.Context) error {
	l.mu.Lock()
	wait := time.Duration(0)
	now := time.Now()
	if !l.last.IsZero() {
		elapsed := now.Sub(l.last)
		if elapsed < l.interval {
			wait = l.interval - elapsed
		}
	}
	l.last = now.Add(wait)
	l.mu.Unlock()

	if wait <= 0 {
		return nil
	}
	return sleep(ctx, wait)
}

func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type RateLimit struct {
	Resource  string
	Limit     int
	Remaining int
	Used      int
	Reset     time.Time
}

func (r RateLimit) Known() bool { return r.Limit > 0 || !r.Reset.IsZero() }

func (r RateLimit) Exhausted() bool { return r.Known() && r.Remaining < rateLimitFloor }

func (r RateLimit) Until() time.Duration {
	if r.Reset.IsZero() {
		return 0
	}
	d := time.Until(r.Reset)
	if d < 0 {
		return 0
	}
	return d + time.Second
}

func parseRateLimit(h http.Header) RateLimit {
	rl := RateLimit{Resource: h.Get("X-RateLimit-Resource")}
	if v, err := strconv.Atoi(h.Get("X-RateLimit-Limit")); err == nil {
		rl.Limit = v
	}
	if v, err := strconv.Atoi(h.Get("X-RateLimit-Remaining")); err == nil {
		rl.Remaining = v
	}
	if v, err := strconv.Atoi(h.Get("X-RateLimit-Used")); err == nil {
		rl.Used = v
	}
	if v, err := strconv.ParseInt(h.Get("X-RateLimit-Reset"), 10, 64); err == nil && v > 0 {
		rl.Reset = time.Unix(v, 0)
	}
	return rl
}

func retryAfter(h http.Header) (time.Duration, bool) {
	v := h.Get("Retry-After")
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(v); err == nil {
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		d := time.Until(t)
		if d < 0 {
			d = 0
		}
		return d, true
	}
	return 0, false
}

func backoffFor(attempt int) time.Duration {
	return growBackoff(secondaryBackoffBase, attempt, 15*time.Minute)
}

func transientBackoff(attempt int) time.Duration {
	return growBackoff(transientBackoffBase, attempt, time.Minute)
}

func growBackoff(base time.Duration, attempt int, cap time.Duration) time.Duration {
	d := base
	for i := 0; i < attempt; i++ {
		d *= 2
		if d > cap {
			return cap
		}
	}
	return d
}
