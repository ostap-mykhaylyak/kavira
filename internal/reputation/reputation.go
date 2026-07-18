// Package reputation tracks the sending reputation of local users,
// domains and outbound IPs, and enforces the warm-up schedule that
// keeps a fresh domain from burning its reputation on day one.
//
// Scores live in 0..100 and decay toward the neutral baseline over
// time, so an old incident does not haunt a sender forever and a
// long-quiet good sender does not keep a score it no longer earns.
package reputation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Score bands, as the specification describes them.
const (
	ScoreExcellent = 100
	ScoreNormal    = 50
	ScoreSuspect   = 20
	ScoreBlocked   = 0
)

// Event is something a sender did that moves its score.
type Event int

const (
	// EventDelivered is a successful delivery.
	EventDelivered Event = iota
	// EventAuthPass is a message that passed SPF/DKIM/DMARC.
	EventAuthPass
	// EventBounce is a hard bounce from the destination.
	EventBounce
	// EventSpamComplaint is a recipient-side spam report.
	EventSpamComplaint
	// EventBlacklisted is an appearance on a public blacklist.
	EventBlacklisted
	// EventAnomaly is a sending pattern that looks compromised.
	EventAnomaly
)

// delta is how many points each event moves the score.
var delta = map[Event]float64{
	EventDelivered:     +0.5,
	EventAuthPass:      +0.2,
	EventBounce:        -2,
	EventSpamComplaint: -15,
	EventBlacklisted:   -30,
	EventAnomaly:       -25,
}

// record is the persisted state of one subject.
type record struct {
	Score    float64   `json:"score"`
	Updated  time.Time `json:"updated"`
	First    time.Time `json:"first_seen"`
	Sent     uint64    `json:"sent"`
	Bounced  uint64    `json:"bounced"`
	Reported uint64    `json:"reported"`
	// DaySent counts today's deliveries for the warm-up cap.
	DaySent uint64    `json:"day_sent"`
	DayFrom time.Time `json:"day_from"`
}

// Store holds reputation records, persisted as one JSON file.
type Store struct {
	mu      sync.Mutex
	path    string
	records map[string]*record
	dirty   bool
	now     func() time.Time // injectable for tests
}

// Open loads the store at path, or starts an empty one.
func Open(path string) (*Store, error) {
	s := &Store{path: path, records: map[string]*record{}, now: time.Now}
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(b, &s.records); err != nil {
		// A corrupt store must not stop the mail server: reputation
		// is advisory, so start fresh and keep going.
		s.records = map[string]*record{}
	}
	return s, nil
}

// get returns the record for a subject, creating it at the neutral
// baseline and applying time decay.
func (s *Store) get(key string) *record {
	r := s.records[key]
	now := s.now()
	if r == nil {
		r = &record{Score: ScoreNormal, Updated: now, First: now, DayFrom: now}
		s.records[key] = r
		s.dirty = true
		return r
	}
	// Decay 1 point per day toward the baseline.
	if days := now.Sub(r.Updated).Hours() / 24; days >= 1 {
		if r.Score < ScoreNormal {
			r.Score = minf(ScoreNormal, r.Score+days)
		} else if r.Score > ScoreNormal {
			r.Score = maxf(ScoreNormal, r.Score-days)
		}
		r.Updated = now
		s.dirty = true
	}
	// Reset the daily counter when the day rolled over.
	if now.Sub(r.DayFrom) >= 24*time.Hour {
		r.DaySent = 0
		r.DayFrom = now
		s.dirty = true
	}
	return r
}

// Record applies an event to a subject and returns the new score.
func (s *Store) Record(key string, e Event) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.get(key)
	r.Score = clamp(r.Score + delta[e])
	r.Updated = s.now()
	switch e {
	case EventDelivered:
		r.Sent++
		r.DaySent++
	case EventBounce:
		r.Bounced++
	case EventSpamComplaint:
		r.Reported++
	}
	s.dirty = true
	return r.Score
}

// Score returns the current score of a subject.
func (s *Store) Score(key string) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.get(key).Score
}

// Blocked reports whether a subject's score has fallen to the point
// where it must not send at all.
func (s *Store) Blocked(key string) bool {
	return s.Score(key) <= ScoreSuspect/2
}

// Stats is a snapshot of one subject, for the admin API.
type Stats struct {
	Key       string    `json:"key"`
	Score     float64   `json:"score"`
	Sent      uint64    `json:"sent"`
	Bounced   uint64    `json:"bounced"`
	Reported  uint64    `json:"reported"`
	DaySent   uint64    `json:"day_sent"`
	FirstSeen time.Time `json:"first_seen"`
}

// Snapshot returns every record, worst score first.
func (s *Store) Snapshot() []Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Stats, 0, len(s.records))
	for k, r := range s.records {
		out = append(out, Stats{
			Key: k, Score: r.Score, Sent: r.Sent, Bounced: r.Bounced,
			Reported: r.Reported, DaySent: r.DaySent, FirstSeen: r.First,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score < out[j].Score })
	return out
}

// Save persists the store if it changed.
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty || s.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s.records, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		os.Remove(tmp)
		return err
	}
	s.dirty = false
	return nil
}

// WarmUp is the ramp a new sending domain follows: the daily cap
// grows with the domain's age, so a fresh IP or domain does not send
// a burst that receivers read as a spam run.
type WarmUp struct {
	// Enabled turns the ramp on.
	Enabled bool
	// Day1 is the cap on the first day.
	Day1 uint64
	// Day7 is the cap reached after a week.
	Day7 uint64
	// Full is the cap after the ramp completes (30 days).
	Full uint64
}

// DailyLimit returns the cap for a domain of the given age.
func (w WarmUp) DailyLimit(age time.Duration) uint64 {
	if !w.Enabled {
		return 0 // unlimited
	}
	days := age.Hours() / 24
	switch {
	case days <= 1:
		return w.Day1
	case days >= 30:
		return w.Full
	case days <= 7:
		// Linear from Day1 to Day7 across the first week.
		f := (days - 1) / 6
		return w.Day1 + uint64(f*float64(w.Day7-w.Day1))
	default:
		// Linear from Day7 to Full across the rest of the month.
		f := (days - 7) / 23
		return w.Day7 + uint64(f*float64(w.Full-w.Day7))
	}
}

// AllowSend reports whether a subject may send one more message under
// the warm-up cap, and the cap that applied.
func (s *Store) AllowSend(key string, w WarmUp) (bool, uint64) {
	if !w.Enabled {
		return true, 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.get(key)
	limit := w.DailyLimit(s.now().Sub(r.First))
	if limit == 0 {
		return true, 0
	}
	return r.DaySent < limit, limit
}

// String renders a score band for logs.
func Band(score float64) string {
	switch {
	case score >= 80:
		return "excellent"
	case score >= 40:
		return "normal"
	case score > ScoreSuspect/2:
		return "suspect"
	default:
		return "blocked"
	}
}

func clamp(v float64) float64 { return maxf(ScoreBlocked, minf(ScoreExcellent, v)) }
func minf(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
func maxf(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
