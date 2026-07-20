// Package stats holds the counters `kavira status` reports.
//
// They are plain atomics updated on the hot path and read on demand:
// no aggregation, no time series, no persistence. An operator asking
// "is this server receiving and sending mail?" gets an answer; anyone
// wanting history should read the JSON log, which already carries
// every event these counters summarize.
//
// Every increment is a method with a nil-safe receiver, so a caller
// without counters wired up needs no conditional. Taking the address
// of a field instead (`&c.Received`) would panic on a nil Counters
// before any check could run.
package stats

import "sync/atomic"

// Counters is the live event tally of one daemon run.
type Counters struct {
	// Inbound.
	received  atomic.Uint64
	rejected  atomic.Uint64
	spam      atomic.Uint64
	relayDeny atomic.Uint64

	// Submission.
	submitted atomic.Uint64
	authOK    atomic.Uint64
	authFail  atomic.Uint64

	// Outbound.
	delivered atomic.Uint64
	bounced   atomic.Uint64
	deferred  atomic.Uint64
}

// Each method checks the receiver before touching a field. Factoring
// the check into a helper that takes &c.field would defeat it: the
// address is computed at the call site, panicking on a nil receiver
// before the helper ever runs.

// Inbound.
func (c *Counters) IncReceived() {
	if c != nil {
		c.received.Add(1)
	}
}

func (c *Counters) IncRejected() {
	if c != nil {
		c.rejected.Add(1)
	}
}

func (c *Counters) IncSpam() {
	if c != nil {
		c.spam.Add(1)
	}
}

func (c *Counters) IncRelayDeny() {
	if c != nil {
		c.relayDeny.Add(1)
	}
}

// Submission.
func (c *Counters) IncSubmitted() {
	if c != nil {
		c.submitted.Add(1)
	}
}

func (c *Counters) IncAuthOK() {
	if c != nil {
		c.authOK.Add(1)
	}
}

func (c *Counters) IncAuthFail() {
	if c != nil {
		c.authFail.Add(1)
	}
}

// Outbound.
func (c *Counters) IncDelivered() {
	if c != nil {
		c.delivered.Add(1)
	}
}

func (c *Counters) IncBounced() {
	if c != nil {
		c.bounced.Add(1)
	}
}

func (c *Counters) IncDeferred() {
	if c != nil {
		c.deferred.Add(1)
	}
}

// Snapshot is a plain-value copy for reporting.
type Snapshot struct {
	Received  uint64 `json:"received"`
	Rejected  uint64 `json:"rejected"`
	Spam      uint64 `json:"spam"`
	RelayDeny uint64 `json:"relay_denied"`
	Submitted uint64 `json:"submitted"`
	AuthOK    uint64 `json:"auth_ok"`
	AuthFail  uint64 `json:"auth_failed"`
	Delivered uint64 `json:"delivered"`
	Bounced   uint64 `json:"bounced"`
	Deferred  uint64 `json:"deferred"`
}

// Snapshot reads every counter. A nil receiver returns zeros.
func (c *Counters) Snapshot() Snapshot {
	if c == nil {
		return Snapshot{}
	}
	return Snapshot{
		Received:  c.received.Load(),
		Rejected:  c.rejected.Load(),
		Spam:      c.spam.Load(),
		RelayDeny: c.relayDeny.Load(),
		Submitted: c.submitted.Load(),
		AuthOK:    c.authOK.Load(),
		AuthFail:  c.authFail.Load(),
		Delivered: c.delivered.Load(),
		Bounced:   c.bounced.Load(),
		Deferred:  c.deferred.Load(),
	}
}
