// Package queue implements the outbound SMTP queue: disk-backed
// envelopes (one per recipient), a scheduler with exponential
// backoff, an MX-based SMTP transport and RFC 3464 bounces.
//
// Every envelope is a single JSON file under the queue directory,
// written atomically (tmp + rename): a crash never leaves a
// half-parsable entry, and the queue survives restarts.
package queue

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ostap-mykhaylyak/kavira/internal/storage"
)

// Envelope is one queued delivery: one message to one recipient.
type Envelope struct {
	ID          string    `json:"id"`
	From        string    `json:"from"` // empty = null reverse-path
	Rcpt        string    `json:"rcpt"`
	Domain      string    `json:"domain"`
	Attempts    int       `json:"attempts"`
	NextAttempt time.Time `json:"next_attempt"`
	Created     time.Time `json:"created"`
	LastError   string    `json:"last_error,omitempty"`
	Data        []byte    `json:"data"`
}

// Queue is the on-disk envelope store.
type Queue struct {
	dir string
}

// Open prepares the queue directory.
func Open(dir string) (*Queue, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("queue: %w", err)
	}
	return &Queue{dir: dir}, nil
}

// Enqueue stores one message for one recipient, due immediately.
func (q *Queue) Enqueue(from, rcpt string, data []byte) error {
	_, domain, ok := storage.Split(rcpt)
	if !ok {
		return fmt.Errorf("queue: invalid recipient %q", rcpt)
	}
	now := time.Now()
	e := &Envelope{
		ID:          newID(now),
		From:        strings.ToLower(from),
		Rcpt:        strings.ToLower(rcpt),
		Domain:      domain,
		NextAttempt: now,
		Created:     now,
		Data:        data,
	}
	return q.write(e)
}

// Due returns the envelopes whose retry time has come, oldest first.
// Unparsable files are skipped (and reported), never deleted: they
// stay on disk for manual inspection.
func (q *Queue) Due(now time.Time) ([]*Envelope, []error) {
	all, errs := q.load()
	due := all[:0]
	for _, e := range all {
		if !e.NextAttempt.After(now) {
			due = append(due, e)
		}
	}
	return due, errs
}

// Size returns the number of queued envelopes.
func (q *Queue) Size() int {
	ents, err := os.ReadDir(q.dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, ent := range ents {
		if strings.HasSuffix(ent.Name(), ".json") {
			n++
		}
	}
	return n
}

// Update persists a modified envelope (attempt count, next retry).
func (q *Queue) Update(e *Envelope) error { return q.write(e) }

// Remove deletes an envelope after final disposition.
func (q *Queue) Remove(e *Envelope) error {
	return os.Remove(q.path(e.ID))
}

func (q *Queue) load() ([]*Envelope, []error) {
	ents, err := os.ReadDir(q.dir)
	if err != nil {
		return nil, []error{err}
	}
	var out []*Envelope
	var errs []error
	for _, ent := range ents {
		if !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(q.dir, ent.Name()))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		var e Envelope
		if err := json.Unmarshal(b, &e); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", ent.Name(), err))
			continue
		}
		out = append(out, &e)
	}
	// Oldest first: fair delivery order.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Created.Before(out[j-1].Created); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out, errs
}

func (q *Queue) path(id string) string {
	return filepath.Join(q.dir, id+".json")
}

func (q *Queue) write(e *Envelope) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	tmp := q.path(e.ID) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, q.path(e.ID)); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// newID builds a sortable unique envelope id.
func newID(now time.Time) string {
	var r [6]byte
	rand.Read(r[:])
	return fmt.Sprintf("%d-%x", now.UnixNano(), binary.BigEndian.Uint32(r[:4]))
}
