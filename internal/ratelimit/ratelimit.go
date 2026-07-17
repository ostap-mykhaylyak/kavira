// Package ratelimit implements per-key token buckets for the inbound
// protections: connections, messages and recipients per source IP.
//
// Each key gets a bucket holding up to perMinute tokens (the burst)
// that refills continuously at perMinute/60 tokens per second: short
// bursts are absorbed, sustained floods are cut to the configured
// rate and recover gradually. Idle buckets are pruned opportunistically
// so the map cannot grow without bound under an address-spraying scan.
package ratelimit

import (
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

// Limiter is one token-bucket family keyed by string (an IP).
type Limiter struct {
	mu      sync.Mutex
	perMin  float64
	buckets map[string]*bucket
	now     func() time.Time // injectable for tests
}

// New returns a Limiter allowing perMinute events per key with a
// burst of the same size.
func New(perMinute int) *Limiter {
	return &Limiter{
		perMin:  float64(perMinute),
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
		b = &bucket{tokens: l.perMin, last: now}
		l.buckets[key] = b
	} else {
		b.tokens += now.Sub(b.last).Seconds() * l.perMin / 60
		if b.tokens > l.perMin {
			b.tokens = l.perMin
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
		idle := now.Sub(b.last).Seconds() * l.perMin / 60
		if b.tokens+idle >= l.perMin {
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
		conns: New(connsPerMin),
		msgs:  New(msgsPerMin),
		rcpts: New(rcptsPerMin),
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
