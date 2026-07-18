package reputation

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testStore(t *testing.T, path string) (*Store, *time.Time) {
	t.Helper()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s.now = func() time.Time { return now }
	return s, &now
}

func TestScoreStartsNeutralAndMoves(t *testing.T) {
	s, _ := testStore(t, "")
	if got := s.Score("user:a@b.it"); got != ScoreNormal {
		t.Errorf("initial score = %v, want %v", got, ScoreNormal)
	}
	s.Record("user:a@b.it", EventSpamComplaint)
	if got := s.Score("user:a@b.it"); got != ScoreNormal-15 {
		t.Errorf("after complaint = %v", got)
	}
	s.Record("user:a@b.it", EventDelivered)
	if got := s.Score("user:a@b.it"); got != ScoreNormal-14.5 {
		t.Errorf("after delivery = %v", got)
	}
}

func TestScoreClamped(t *testing.T) {
	s, _ := testStore(t, "")
	for i := 0; i < 10; i++ {
		s.Record("k", EventBlacklisted)
	}
	if got := s.Score("k"); got != ScoreBlocked {
		t.Errorf("score floor = %v, want %v", got, ScoreBlocked)
	}
	for i := 0; i < 500; i++ {
		s.Record("k2", EventDelivered)
	}
	if got := s.Score("k2"); got != ScoreExcellent {
		t.Errorf("score ceiling = %v, want %v", got, ScoreExcellent)
	}
}

func TestBlockedThreshold(t *testing.T) {
	s, _ := testStore(t, "")
	if s.Blocked("k") {
		t.Error("a fresh sender must not be blocked")
	}
	s.Record("k", EventBlacklisted) // 50 -> 20
	if s.Blocked("k") {
		t.Error("a suspect sender is not yet blocked")
	}
	s.Record("k", EventAnomaly) // 20 -> 0
	if !s.Blocked("k") {
		t.Error("a zero-score sender must be blocked")
	}
}

func TestDecayTowardBaseline(t *testing.T) {
	s, now := testStore(t, "")
	s.Record("k", EventBlacklisted) // 50 -> 20
	if got := s.Score("k"); got != 20 {
		t.Fatalf("score = %v", got)
	}
	// Ten days later the score has climbed back toward neutral.
	*now = now.Add(10 * 24 * time.Hour)
	if got := s.Score("k"); got != 30 {
		t.Errorf("after 10 days = %v, want 30", got)
	}
	// It never overshoots the baseline.
	*now = now.Add(100 * 24 * time.Hour)
	if got := s.Score("k"); got != ScoreNormal {
		t.Errorf("decay must stop at the baseline, got %v", got)
	}

	// A good sender decays downward to the baseline too.
	for i := 0; i < 100; i++ {
		s.Record("good", EventDelivered)
	}
	if got := s.Score("good"); got != ScoreExcellent {
		t.Fatalf("score = %v", got)
	}
	*now = now.Add(200 * 24 * time.Hour)
	if got := s.Score("good"); got != ScoreNormal {
		t.Errorf("high score must also decay to the baseline, got %v", got)
	}
}

func TestWarmUpRamp(t *testing.T) {
	w := WarmUp{Enabled: true, Day1: 100, Day7: 2000, Full: 50000}
	cases := []struct {
		days float64
		want uint64
	}{
		{0, 100},
		{1, 100},
		{7, 2000},
		{30, 50000},
		{365, 50000},
	}
	for _, c := range cases {
		got := w.DailyLimit(time.Duration(c.days * 24 * float64(time.Hour)))
		if got != c.want {
			t.Errorf("day %.0f limit = %d, want %d", c.days, got, c.want)
		}
	}
	// The ramp is monotonic: never a step backwards.
	var prev uint64
	for d := 0.0; d <= 35; d += 0.5 {
		got := w.DailyLimit(time.Duration(d * 24 * float64(time.Hour)))
		if got < prev {
			t.Fatalf("ramp went backwards at day %.1f: %d after %d", d, got, prev)
		}
		prev = got
	}
	// Disabled means unlimited.
	if got := (WarmUp{}).DailyLimit(0); got != 0 {
		t.Errorf("disabled warm-up limit = %d, want 0 (unlimited)", got)
	}
}

func TestAllowSendEnforcesDailyCap(t *testing.T) {
	s, now := testStore(t, "")
	w := WarmUp{Enabled: true, Day1: 3, Day7: 10, Full: 100}

	for i := 0; i < 3; i++ {
		ok, limit := s.AllowSend("domain:nuovo.it", w)
		if !ok {
			t.Fatalf("send %d refused under a cap of %d", i+1, limit)
		}
		s.Record("domain:nuovo.it", EventDelivered)
	}
	ok, limit := s.AllowSend("domain:nuovo.it", w)
	if ok {
		t.Errorf("the 4th send must exceed the day-1 cap of %d", limit)
	}

	// The next day the counter resets.
	*now = now.Add(25 * time.Hour)
	if ok, _ := s.AllowSend("domain:nuovo.it", w); !ok {
		t.Error("the daily counter must reset after 24h")
	}
}

func TestPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reputation.json")
	s, _ := testStore(t, path)
	s.Record("user:a@b.it", EventSpamComplaint)
	s.Record("domain:b.it", EventDelivered)
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := s2.Score("user:a@b.it"); got != ScoreNormal-15 {
		t.Errorf("reloaded score = %v", got)
	}
	snap := s2.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("snapshot = %v", snap)
	}
	// Worst score first, so an operator sees the problems on top.
	if snap[0].Key != "user:a@b.it" {
		t.Errorf("snapshot order = %v", snap)
	}
	if snap[0].Reported != 1 {
		t.Errorf("complaint counter = %d", snap[0].Reported)
	}
}

func TestCorruptStoreStartsFresh(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reputation.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatalf("a corrupt store must not fail the daemon: %v", err)
	}
	if got := s.Score("k"); got != ScoreNormal {
		t.Errorf("score = %v", got)
	}
}

func TestBands(t *testing.T) {
	cases := map[float64]string{100: "excellent", 80: "excellent", 50: "normal", 40: "normal", 15: "suspect", 5: "blocked", 0: "blocked"}
	for score, want := range cases {
		if got := Band(score); got != want {
			t.Errorf("Band(%v) = %q, want %q", score, got, want)
		}
	}
}
