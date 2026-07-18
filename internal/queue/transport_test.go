package queue

import (
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ostap-mykhaylyak/kavira/internal/maildir"
	"github.com/ostap-mykhaylyak/kavira/internal/smtp"
	"github.com/ostap-mykhaylyak/kavira/internal/storage"
)

// TestTransportDeliversToRealServer runs the full outbound path:
// queue -> scheduler -> SMTPTransport -> a real inbound SMTP server
// -> Maildir.
func TestTransportDeliversToRealServer(t *testing.T) {
	root := t.TempDir()

	// Destination: an inbound kavira server for remote.org.
	backend := smtp.Backend{
		IsLocalDomain: func(d string) bool { return d == "remote.org" },
		Lookup: func(email string) (storage.Mailbox, bool) {
			if email == "friend@remote.org" {
				return storage.Mailbox{Email: email, Dir: filepath.Join(root, "friend"), UID: -1, GID: -1}, true
			}
			return storage.Mailbox{}, false
		},
		Deliver: func(mb storage.Mailbox, from string, spam bool, msg []byte) error {
			_, err := maildir.Deliver(mb.Dir, msg, mb.UID, mb.GID)
			return err
		},
		Postmaster: func() string { return "" },
	}
	srv := smtp.New(smtp.Settings{
		Hostname: "mx.remote.org", MaxSize: 1 << 20, MaxRecipients: 10,
	}, backend, 4, quietLog())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Shutdown(2 * time.Second) })
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	// Origin: queue + scheduler + real SMTP transport, MX overridden
	// to the test listener.
	q, _ := Open(t.TempDir())
	q.Enqueue("sender@here.it", "friend@remote.org",
		[]byte("Subject: via queue\r\n\r\nconsegnata\r\n"))
	tr := &SMTPTransport{
		Hostname: "mail.here.it",
		Port:     atoi(port),
		LookupMX: func(domain string) ([]string, error) { return []string{"127.0.0.1"}, nil },
		Timeout:  5 * time.Second,
	}
	s := NewScheduler(q, tr, func(e *Envelope, r string) { t.Errorf("unexpected bounce: %s", r) }, 3, quietLog())
	s.Process(time.Now())

	if q.Size() != 0 {
		t.Fatal("envelope should be delivered and removed")
	}
	ents, err := os.ReadDir(filepath.Join(root, "friend", "new"))
	if err != nil || len(ents) != 1 {
		t.Fatalf("message not delivered: %v (%v)", ents, err)
	}
	msg, _ := os.ReadFile(filepath.Join(root, "friend", "new", ents[0].Name()))
	if !strings.Contains(string(msg), "consegnata") {
		t.Errorf("body lost:\n%s", msg)
	}
}

// TestTransportPermanentFromServer maps a 550 from the remote server
// to a PermanentError (bounce, no retry).
func TestTransportPermanentFromServer(t *testing.T) {
	backend := smtp.Backend{
		IsLocalDomain: func(d string) bool { return d == "remote.org" },
		Lookup:        func(string) (storage.Mailbox, bool) { return storage.Mailbox{}, false },
		Deliver:       func(storage.Mailbox, string, bool, []byte) error { return nil },
		Postmaster:    func() string { return "" },
	}
	srv := smtp.New(smtp.Settings{
		Hostname: "mx.remote.org", MaxSize: 1 << 20, MaxRecipients: 10,
	}, backend, 4, quietLog())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Shutdown(2 * time.Second) })
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	q, _ := Open(t.TempDir())
	q.Enqueue("sender@here.it", "ghost@remote.org", []byte("m"))
	tr := &SMTPTransport{
		Hostname: "mail.here.it",
		Port:     atoi(port),
		LookupMX: func(string) ([]string, error) { return []string{"127.0.0.1"}, nil },
		Timeout:  5 * time.Second,
	}
	bounced := false
	s := NewScheduler(q, tr, func(e *Envelope, r string) {
		bounced = true
		if !strings.Contains(r, "550") {
			t.Errorf("reason should carry the 550: %q", r)
		}
	}, 3, quietLog())
	s.Process(time.Now())

	if !bounced {
		t.Fatal("want immediate bounce on 550")
	}
	if q.Size() != 0 {
		t.Error("bounced envelope must be removed")
	}
}

func quietLog() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}
