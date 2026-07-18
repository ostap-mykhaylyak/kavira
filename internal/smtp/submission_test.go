package smtp

import (
	"bufio"
	stdtls "crypto/tls"
	"encoding/base64"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ostap-mykhaylyak/kavira/internal/auth"
	"github.com/ostap-mykhaylyak/kavira/internal/maildir"
	"github.com/ostap-mykhaylyak/kavira/internal/ratelimit"
	"github.com/ostap-mykhaylyak/kavira/internal/storage"
)

// enqueueLog captures Enqueue calls.
type enqueueLog struct {
	mu    sync.Mutex
	calls []string
}

func (e *enqueueLog) add(rcpt string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls = append(e.calls, rcpt)
}

func (e *enqueueLog) list() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.calls...)
}

// submissionServer starts a ModeSubmission server on an implicit-TLS
// listener (the 465 personality: simplest to test AUTH against).
func submissionServer(t *testing.T, mailRoot string, mutate func(*Settings)) (addr string, enq *enqueueLog) {
	t.Helper()
	hash, err := auth.HashArgon2id("pw")
	if err != nil {
		t.Fatal(err)
	}
	authr := auth.New(func(email string) (string, bool) {
		if email == "admin@example.com" {
			return hash, true
		}
		return "", false
	}, 3, time.Minute)

	set := Settings{
		Hostname:      "mail.example.com",
		MaxSize:       64 * 1024,
		MaxRecipients: 10,
		Mode:          ModeSubmission,
		ImplicitTLS:   true,
	}
	if mutate != nil {
		mutate(&set)
	}
	enq = &enqueueLog{}
	backend := Backend{
		IsLocalDomain: func(d string) bool { return d == "example.com" },
		Lookup: func(email string) (storage.Mailbox, bool) {
			if email == "admin@example.com" {
				return storage.Mailbox{Email: email, Dir: filepath.Join(mailRoot, "admin"), UID: -1, GID: -1}, true
			}
			return storage.Mailbox{}, false
		},
		Deliver: func(mb storage.Mailbox, from string, spam bool, msg []byte) error {
			_, err := maildir.Deliver(mb.Dir, msg, mb.UID, mb.GID)
			return err
		},
		Postmaster:   func() string { return "admin@example.com" },
		Authenticate: authr.Verify,
		Enqueue: func(from, rcpt string, data []byte) error {
			enq.add(rcpt)
			return nil
		},
	}
	srv := New(set, backend, 8, slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tln := stdtls.NewListener(ln, testTLSConfig(t))
	go srv.Serve(tln)
	t.Cleanup(func() { srv.Shutdown(2 * time.Second) })
	return ln.Addr().String(), enq
}

func dialTLS(t *testing.T, addr string) *client {
	t.Helper()
	conn, err := stdtls.Dial("tcp", addr, &stdtls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	return &client{t: t, conn: conn, r: bufio.NewReader(conn)}
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func authPlainArg(user, pass string) string {
	return b64("\x00" + user + "\x00" + pass)
}

func TestSubmissionRequiresAuth(t *testing.T) {
	addr, _ := submissionServer(t, t.TempDir(), nil)
	c := dialTLS(t, addr)
	c.expect("220")
	c.send("EHLO client.test")
	if caps := c.expect("250"); !strings.Contains(caps, "AUTH PLAIN LOGIN") {
		t.Fatalf("AUTH not advertised over TLS: %q", caps)
	}
	c.send("MAIL FROM:<admin@example.com>")
	c.expect("530") // authentication required
}

func TestSubmissionAuthPlainAndRelay(t *testing.T) {
	root := t.TempDir()
	addr, enq := submissionServer(t, root, nil)
	c := dialTLS(t, addr)
	c.expect("220")
	c.send("EHLO client.test")
	c.expect("250")
	c.send("AUTH PLAIN " + authPlainArg("admin@example.com", "pw"))
	c.expect("235")
	c.send("MAIL FROM:<admin@example.com>")
	c.expect("250")
	c.send("RCPT TO:<friend@remote.org>") // relay: allowed after AUTH
	c.expect("250")
	c.send("RCPT TO:<admin@example.com>") // local copy
	c.expect("250")
	c.send("DATA")
	c.expect("354")
	c.send("Subject: out\r\n\r\nciao\r\n.")
	c.expect("250")

	if got := enq.list(); len(got) != 1 || got[0] != "friend@remote.org" {
		t.Errorf("enqueued = %v", got)
	}
	ents, err := os.ReadDir(filepath.Join(root, "admin", "new"))
	if err != nil || len(ents) != 1 {
		t.Fatalf("local copy not delivered: %v (%v)", ents, err)
	}
	msg, _ := os.ReadFile(filepath.Join(root, "admin", "new", ents[0].Name()))
	if !strings.Contains(string(msg), "with ESMTPSA") {
		t.Errorf("Received should say ESMTPSA:\n%s", msg)
	}
}

func TestSubmissionAuthLogin(t *testing.T) {
	addr, _ := submissionServer(t, t.TempDir(), nil)
	c := dialTLS(t, addr)
	c.expect("220")
	c.send("EHLO x.test")
	c.expect("250")
	c.send("AUTH LOGIN")
	c.expect("334") // Username:
	c.send(b64("admin@example.com"))
	c.expect("334") // Password:
	c.send(b64("pw"))
	c.expect("235")
}

func TestSubmissionWrongPasswordThenLockout(t *testing.T) {
	addr, _ := submissionServer(t, t.TempDir(), nil)
	c := dialTLS(t, addr)
	c.expect("220")
	c.send("EHLO x.test")
	c.expect("250")
	for i := 0; i < 3; i++ {
		c.send("AUTH PLAIN " + authPlainArg("admin@example.com", "wrong"))
		c.expect("535")
	}
	// Guard locked: even the right password is refused now.
	c.send("AUTH PLAIN " + authPlainArg("admin@example.com", "pw"))
	c.expect("454")
}

func TestSubmissionSenderMustMatchAuth(t *testing.T) {
	addr, _ := submissionServer(t, t.TempDir(), nil)
	c := dialTLS(t, addr)
	c.expect("220")
	c.send("EHLO x.test")
	c.expect("250")
	c.send("AUTH PLAIN " + authPlainArg("admin@example.com", "pw"))
	c.expect("235")
	c.send("MAIL FROM:<ceo@bigcorp.com>")
	c.expect("553") // spoofed sender refused
}

func TestSubmissionOutboundMessageQuota(t *testing.T) {
	addr, _ := submissionServer(t, t.TempDir(), func(s *Settings) {
		s.OutLimits = ratelimit.NewOutbound(1, 100)
	})
	c := dialTLS(t, addr)
	c.expect("220")
	c.send("EHLO x.test")
	c.expect("250")
	c.send("AUTH PLAIN " + authPlainArg("admin@example.com", "pw"))
	c.expect("235")
	for i := 0; i < 2; i++ {
		c.send("MAIL FROM:<admin@example.com>")
		c.expect("250")
		c.send("RCPT TO:<friend@remote.org>")
		c.expect("250")
		c.send("DATA")
		if i == 0 {
			c.expect("354")
			c.send("m\r\n.")
			c.expect("250")
		} else {
			c.expect("452") // quota exceeded
			c.send("RSET")
			c.expect("250")
		}
	}
}

func TestInboundStillRefusesAuth(t *testing.T) {
	addr := testServer(t, t.TempDir(), nil) // ModeInbound from server_test
	c := dial(t, addr)
	c.expect("220")
	c.send("EHLO x.test")
	if caps := c.expect("250"); strings.Contains(caps, "AUTH") {
		t.Errorf("inbound must not advertise AUTH: %q", caps)
	}
	c.send("AUTH PLAIN " + authPlainArg("admin@example.com", "pw"))
	c.expect("503")
}

func TestAuthRefusedWithoutTLS(t *testing.T) {
	// Submission on a PLAIN listener (587 personality before
	// STARTTLS): AUTH must be refused until the channel is encrypted.
	root := t.TempDir()
	hash, _ := auth.HashArgon2id("pw")
	authr := auth.New(func(string) (string, bool) { return hash, true }, 3, time.Minute)
	set := Settings{
		Hostname: "mail.example.com", MaxSize: 1024, MaxRecipients: 5,
		Mode: ModeSubmission, TLS: testTLSConfig(t),
	}
	backend := Backend{
		IsLocalDomain: func(string) bool { return false },
		Lookup:        func(string) (storage.Mailbox, bool) { return storage.Mailbox{}, false },
		Deliver:       func(storage.Mailbox, string, bool, []byte) error { return nil },
		Postmaster:    func() string { return "" },
		Authenticate:  authr.Verify,
		Enqueue:       func(string, string, []byte) error { return nil },
	}
	srv := New(set, backend, 4, slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Shutdown(2 * time.Second) })
	_ = root

	c := dial(t, ln.Addr().String())
	c.expect("220")
	c.send("EHLO x.test")
	caps := c.expect("250")
	if strings.Contains(caps, "AUTH") {
		t.Errorf("AUTH advertised on plaintext channel: %q", caps)
	}
	if !strings.Contains(caps, "STARTTLS") {
		t.Errorf("STARTTLS missing: %q", caps)
	}
	c.send("AUTH PLAIN " + authPlainArg("a@b.c", "pw"))
	c.expect("530") // must STARTTLS first
}
