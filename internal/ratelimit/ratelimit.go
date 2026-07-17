// Package ratelimit implements per-key token buckets for the flood
// protections: inbound per-IP limits (connections, messages,
// recipients per minute) and outbound per-user limits (messages,
// recipients per hour).
//
// Each key gets a bucket holding up to limit tokens (the burst) that
// refills continuously at limit/window: short bursts are absorbed,
// sustained floods are cut to the configured rate and recover
// gradually. Idle buckets are pruned opportunistically so the map
// cannot grow without bound under an address-spraying scan.
package ratelimit

import (
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

// Limiter is one token-bucket family keyed by string (an IP, a user).
type Limiter struct {
	mu      sync.Mutex
	limit   float64
	window  time.Duration
	buckets map[string]*bucket
	now     func() time.Time // injectable for tests
}

// New returns a Limiter allowing limit events per window per key,
// with a burst of the same size.
func New(limit int, window time.Duration) *Limiter {
	return &Limiter{
		limit:   float64(limit),
		window:  window,
		buckets: make(map[string]*bucket),
		now:     time.Now,
	}
}

// Allow consumes one token for key, reporting whether it was
// available.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	b := l.buckets[key]
	if b == nil {
		if len(l.buckets) >= 65536 {
			l.prune(now)
		}
		b = &bucket{tokens: l.limit, last: now}
		l.buckets[key] = b
	} else {
		b.tokens += float64(now.Sub(b.last)) / float64(l.window) * l.limit
		if b.tokens > l.limit {
			b.tokens = l.limit
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// prune drops buckets that refilled completely (idle long enough to
// carry no state). Called with the lock held.
func (l *Limiter) prune(now time.Time) {
	for k, b := range l.buckets {
		idle := float64(now.Sub(b.last)) / float64(l.window) * l.limit
		if b.tokens+idle >= l.limit {
			delete(l.buckets, k)
		}
	}
}

// Inbound bundles the three per-IP inbound limiters. A nil Inbound
// allows everything (rate limiting disabled).
type Inbound struct {
	conns *Limiter
	msgs  *Limiter
	rcpts *Limiter
}

// NewInbound builds the inbound limiter set from per-minute values.
func NewInbound(connsPerMin, msgsPerMin, rcptsPerMin int) *Inbound {
	return &Inbound{
		conns: New(connsPerMin, time.Minute),
		msgs:  New(msgsPerMin, time.Minute),
		rcpts: New(rcptsPerMin, time.Minute),
	}
}

// ConnAllowed reports whether ip may open one more connection.
func (i *Inbound) ConnAllowed(ip string) bool {
	return i == nil || i.conns.Allow(ip)
}

// MsgAllowed reports whether ip may submit one more message.
func (i *Inbound) MsgAllowed(ip string) bool {
	return i == nil || i.msgs.Allow(ip)
}

// RcptAllowed reports whether ip may address one more recipient.
func (i *Inbound) RcptAllowed(ip string) bool {
	return i == nil || i.rcpts.Allow(ip)
}

// Outbound bundles the per-user sending limiters (compromised account
// protection). A nil Outbound allows everything.
type Outbound struct {
	msgs  *Limiter
	rcpts *Limiter
}

// NewOutbound builds the outbound limiter set from per-hour values.
func NewOutbound(msgsPerHour, rcptsPerHour int) *Outbound {
	return &Outbound{
		msgs:  New(msgsPerHour, time.Hour),
		rcpts: New(rcptsPerHour, time.Hour),
	}
}

// MsgAllowed reports whether user may send one more message.
func (o *Outbound) MsgAllowed(user string) bool {
	return o == nil || o.msgs.Allow(user)
}

// RcptAllowed reports whether user may address one more recipient.
func (o *Outbound) RcptAllowed(user string) bool {
	return o == nil || o.rcpts.Allow(user)
}
