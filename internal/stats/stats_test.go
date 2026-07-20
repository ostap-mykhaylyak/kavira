package stats

import (
	"sync"
	"testing"
)

// A nil Counters is the normal case for any caller that does not wire
// statistics up — every test server in this repository, for one. The
// increments must be no-ops, not a panic. An earlier version factored
// the nil check into a helper taking &c.field, which panicked at the
// call site before the check could run; this test is what caught it.
func TestNilCountersAreSafe(t *testing.T) {
	var c *Counters
	for name, inc := range map[string]func(){
		"IncReceived":  c.IncReceived,
		"IncRejected":  c.IncRejected,
		"IncSpam":      c.IncSpam,
		"IncRelayDeny": c.IncRelayDeny,
		"IncSubmitted": c.IncSubmitted,
		"IncAuthOK":    c.IncAuthOK,
		"IncAuthFail":  c.IncAuthFail,
		"IncDelivered": c.IncDelivered,
		"IncBounced":   c.IncBounced,
		"IncDeferred":  c.IncDeferred,
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s panicked on a nil Counters: %v", name, r)
				}
			}()
			inc()
		}()
	}
	if got := c.Snapshot(); got != (Snapshot{}) {
		t.Errorf("nil Snapshot = %+v, want zeros", got)
	}
}

func TestCountersRecord(t *testing.T) {
	c := &Counters{}
	c.IncReceived()
	c.IncReceived()
	c.IncSpam()
	c.IncAuthFail()
	c.IncDelivered()

	got := c.Snapshot()
	if got.Received != 2 {
		t.Errorf("received = %d, want 2", got.Received)
	}
	if got.Spam != 1 || got.AuthFail != 1 || got.Delivered != 1 {
		t.Errorf("snapshot = %+v", got)
	}
	// Untouched counters stay at zero.
	if got.Bounced != 0 || got.RelayDeny != 0 {
		t.Errorf("untouched counters moved: %+v", got)
	}
}

func TestCountersConcurrent(t *testing.T) {
	c := &Counters{}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				c.IncReceived()
			}
		}()
	}
	wg.Wait()
	if got := c.Snapshot().Received; got != 5000 {
		t.Errorf("received = %d, want 5000", got)
	}
}
