package auth

import (
	"sync"
	"time"
)

// Guard tracks failed authentication attempts per key (an IP, a
// user) and answers two questions: is this key locked out, and how
// long should the next failure response be delayed.
type Guard struct {
	mu          sync.Mutex
	maxFailures int
	lockout     time.Duration
	entries     map[string]*guardEntry
	now         func() time.Time // injectable for tests
}

type guardEntry struct {
	fails       int
	lockedUntil time.Time
	last        time.Time
}

// NewGuard builds a Guard locking a key for lockout after maxFailures
// consecutive failures.
func NewGuard(maxFailures int, lockout time.Duration) *Guard {
	return &Guard{
		maxFailures: maxFailures,
		lockout:     lockout,
		entries:     make(map[string]*guardEntry),
		now:         time.Now,
	}
}

// Blocked reports whether key is currently locked out.
func (g *Guard) Blocked(key string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	e := g.entries[key]
	return e != nil && g.now().Before(e.lockedUntil)
}

// Fail records a failed attempt for key and returns the progressive
// delay to apply before answering: 250ms doubling per failure, capped
// at 4s. Reaching maxFailures locks the key out.
func (g *Guard) Fail(key string) time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.now()
	e := g.entries[key]
	if e == nil {
		if len(g.entries) >= 65536 {
			g.prune(now)
		}
		e = &guardEntry{}
		g.entries[key] = e
	}
	// A quiet period twice the lockout forgives old failures.
	if now.Sub(e.last) > 2*g.lockout {
		e.fails = 0
	}
	e.fails++
	e.last = now
	if e.fails >= g.maxFailures {
		e.lockedUntil = now.Add(g.lockout)
	}
	shift := e.fails - 1
	if shift > 4 {
		shift = 4
	}
	return 250 * time.Millisecond << shift
}

// Success clears the failure state of key.
func (g *Guard) Success(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.entries, key)
}

// prune drops entries whose state no longer matters. Called with the
// lock held.
func (g *Guard) prune(now time.Time) {
	for k, e := range g.entries {
		if now.After(e.lockedUntil) && now.Sub(e.last) > 2*g.lockout {
			delete(g.entries, k)
		}
	}
}
