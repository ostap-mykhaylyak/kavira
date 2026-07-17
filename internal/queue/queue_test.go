package queue

import (
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"
)

func testLog() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestEnqueuePersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue("a@here.it", "b@there.org", []byte("Subject: x\r\n\r\nbody")); err != nil {
		t.Fatal(err)
	}

	q2, err := Open(dir) // simulate restart
	if err != nil {
		t.Fatal(err)
	}
	due, errs := q2.Due(time.Now())
	if len(errs) != 0 || len(due) != 1 {
		t.Fatalf("due = %v, errs = %v", due, errs)
	}
	e := due[0]
	if e.From != "a@here.it" || e.Rcpt != "b@there.org" || e.Domain != "there.org" {
		t.Errorf("envelope = %+v", e)
	}
	if string(e.Data) != "Subject: x\r\n\r\nbody" {
		t.Errorf("data = %q", e.Data)
	}
	if q2.Size() != 1 {
		t.Errorf("size = %d", q2.Size())
	}
}

func TestDueRespectsNextAttempt(t *testing.T) {
	q, _ := Open(t.TempDir())
	q.Enqueue("a@x.it", "b@y.org", []byte("m"))
	due, _ := q.Due(time.Now())
	if len(due) != 1 {
		t.Fatal("want due immediately")
	}
	e := due[0]
	e.NextAttempt = time.Now().Add(time.Hour)
	if err := q.Update(e); err != nil {
		t.Fatal(err)
	}
	if due, _ := q.Due(time.Now()); len(due) != 0 {
		t.Fatal("must not be due before next_attempt")
	}
	if due, _ := q.Due(time.Now().Add(2 * time.Hour)); len(due) != 1 {
		t.Fatal("must be due after next_attempt")
	}
}

// fakeTransport scripts delivery outcomes per recipient.
type fakeTransport struct {
	outcome map[string]error
	calls   []string
}

func (f *fakeTransport) Deliver(e *Envelope) error {
	f.calls = append(f.calls, e.Rcpt)
	return f.outcome[e.Rcpt]
}

func TestSchedulerSuccessRemoves(t *testing.T) {
	q, _ := Open(t.TempDir())
	q.Enqueue("a@x.it", "ok@y.org", []byte("m"))
	ft := &fakeTransport{outcome: map[string]error{"ok@y.org": nil}}
	s := NewScheduler(q, ft, func(*Envelope, string) { t.Error("unexpected bounce") }, 3, testLog())

	s.Process(time.Now())
	if q.Size() != 0 {
		t.Error("delivered envelope must be removed")
	}
}

func TestSchedulerPermanentBouncesImmediately(t *testing.T) {
	q, _ := Open(t.TempDir())
	q.Enqueue("sender@x.it", "nouser@y.org", []byte("Subject: hi\r\n\r\nb"))
	ft := &fakeTransport{outcome: map[string]error{
		"nouser@y.org": &PermanentError{Code: 550, Msg: "no such user"},
	}}
	var bounced *Envelope
	var reason string
	s := NewScheduler(q, ft, func(e *Envelope, r string) { bounced, reason = e, r }, 3, testLog())

	s.Process(time.Now())
	if bounced == nil || bounced.Rcpt != "nouser@y.org" {
		t.Fatalf("want bounce, got %+v", bounced)
	}
	if !strings.Contains(reason, "550") {
		t.Errorf("reason = %q", reason)
	}
	if q.Size() != 0 {
		t.Error("bounced envelope must be removed")
	}
	if len(ft.calls) != 1 {
		t.Errorf("permanent failure must not retry: %v", ft.calls)
	}
}

func TestSchedulerTransientRetriesThenBounces(t *testing.T) {
	q, _ := Open(t.TempDir())
	q.Enqueue("sender@x.it", "busy@y.org", []byte("m"))
	ft := &fakeTransport{outcome: map[string]error{"busy@y.org": errors.New("connection refused")}}
	var bounces int
	s := NewScheduler(q, ft, func(*Envelope, string) { bounces++ }, 3, testLog())

	now := time.Now()
	s.Process(now) // attempt 1 -> defer +1m
	if q.Size() != 1 || bounces != 0 {
		t.Fatalf("after 1st: size=%d bounces=%d", q.Size(), bounces)
	}
	due, _ := q.Due(now)
	if len(due) != 0 {
		t.Fatal("must be deferred, not due")
	}
	s.Process(now.Add(2 * time.Minute))  // attempt 2 -> defer +2m
	s.Process(now.Add(10 * time.Minute)) // attempt 3 -> exhausted -> bounce
	if bounces != 1 {
		t.Fatalf("want 1 bounce after exhausted retries, got %d", bounces)
	}
	if q.Size() != 0 {
		t.Error("exhausted envelope must be removed")
	}
	if len(ft.calls) != 3 {
		t.Errorf("want 3 attempts, got %d", len(ft.calls))
	}
}

func TestBackoffProgression(t *testing.T) {
	for i, want := range []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute} {
		if got := backoff(i + 1); got != want {
			t.Errorf("backoff(%d) = %v, want %v", i+1, got, want)
		}
	}
	if got := backoff(20); got != 4*time.Hour {
		t.Errorf("backoff cap = %v", got)
	}
}

func TestBuildBounce(t *testing.T) {
	e := &Envelope{
		ID:   "test-1",
		From: "sender@here.it",
		Rcpt: "gone@there.org",
		Data: []byte("From: sender@here.it\r\nSubject: original\r\n\r\nsecret body"),
	}
	b := BuildBounce("mail.example.com", e, "550 no such user")
	text := string(b)
	for _, want := range []string{
		"From: Mail Delivery System <MAILER-DAEMON@mail.example.com>",
		"To: <sender@here.it>",
		"multipart/report", "report-type=delivery-status",
		"Reporting-MTA: dns; mail.example.com",
		"Final-Recipient: rfc822; gone@there.org",
		"Action: failed",
		"Diagnostic-Code: smtp; 550 no such user",
		"Subject: original", // original headers included
	} {
		if !strings.Contains(text, want) {
			t.Errorf("bounce missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "secret body") {
		t.Error("bounce must carry headers only, not the body")
	}
}

func TestNeverBounceNullSender(t *testing.T) {
	e := &Envelope{ID: "x", From: "", Rcpt: "a@b.org", Data: []byte("m")}
	if b := BuildBounce("h", e, "r"); b != nil {
		t.Error("null reverse-path must never generate a bounce")
	}
}
