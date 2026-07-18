package smtp

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ostap-mykhaylyak/kavira/internal/maildir"
	"github.com/ostap-mykhaylyak/kavira/internal/ratelimit"
	"github.com/ostap-mykhaylyak/kavira/internal/storage"
)

// testServer starts a Server on a random port and returns its address.
func testServer(t *testing.T, mailRoot string, mutate func(*Settings)) string {
	t.Helper()
	set := Settings{
		Hostname:      "mail.example.com",
		MaxSize:       64 * 1024,
		MaxRecipients: 3,
	}
	if mutate != nil {
		mutate(&set)
	}
	backend := Backend{
		IsLocalDomain: func(d string) bool { return d == "example.com" },
		Lookup: func(email string) (storage.Mailbox, bool) {
			if email == "admin@example.com" {
				return storage.Mailbox{Email: email, Dir: filepath.Join(mailRoot, "admin"), UID: -1, GID: -1}, true
			}
			return storage.Mailbox{}, false
		},
		Deliver: func(mb storage.Mailbox, from string, spam bool, msg []byte) error {
			dir := mb.Dir
			if spam {
				dir = filepath.Join(dir, ".Spam")
			}
			full := append([]byte("Return-Path: <"+from+">\r\n"), msg...)
			_, err := maildir.Deliver(dir, full, mb.UID, mb.GID)
			return err
		},
		Postmaster: func() string { return "admin@example.com" },
	}
	srv := New(set, backend, 8, slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Shutdown(2 * time.Second) })
	return ln.Addr().String()
}

// client is a minimal scripted SMTP client.
type client struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
}

func dial(t *testing.T, addr string) *client {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	return &client{t: t, conn: conn, r: bufio.NewReader(conn)}
}

// expect reads one (possibly multi-line) reply and asserts its code.
func (c *client) expect(code string) string {
	c.t.Helper()
	var full strings.Builder
	for {
		line, err := c.r.ReadString('\n')
		if err != nil {
			c.t.Fatalf("read reply: %v (so far %q)", err, full.String())
		}
		full.WriteString(line)
		if len(line) >= 4 && line[3] == ' ' {
			if !strings.HasPrefix(line, code) {
				c.t.Fatalf("reply %q, want code %s", full.String(), code)
			}
			return full.String()
		}
	}
}

func (c *client) send(line string) {
	c.t.Helper()
	if _, err := c.conn.Write([]byte(line + "\r\n")); err != nil {
		c.t.Fatal(err)
	}
}

func TestDeliverToVirtualMailbox(t *testing.T) {
	root := t.TempDir()
	addr := testServer(t, root, nil)

	c := dial(t, addr)
	if got := c.expect("220"); !strings.Contains(got, "mail.example.com ESMTP Kavira") {
		t.Errorf("banner = %q", got)
	}
	c.send("EHLO client.test")
	caps := c.expect("250")
	for _, want := range []string{"PIPELINING", "SIZE 65536", "8BITMIME", "SMTPUTF8"} {
		if !strings.Contains(caps, want) {
			t.Errorf("EHLO missing %s in %q", want, caps)
		}
	}
	if strings.Contains(caps, "STARTTLS") {
		t.Error("STARTTLS advertised without TLS config")
	}
	c.send("MAIL FROM:<sender@elsewhere.org>")
	c.expect("250")
	c.send("RCPT TO:<Admin@Example.Com>")
	c.expect("250")
	c.send("DATA")
	c.expect("354")
	c.send("Subject: test\r\n\r\nhello\r\n.")
	c.expect("250")
	c.send("QUIT")
	c.expect("221")

	ents, err := os.ReadDir(filepath.Join(root, "admin", "new"))
	if err != nil || len(ents) != 1 {
		t.Fatalf("want 1 delivered message, got %v (%v)", ents, err)
	}
	msg, _ := os.ReadFile(filepath.Join(root, "admin", "new", ents[0].Name()))
	text := string(msg)
	if !strings.Contains(text, "Return-Path: <sender@elsewhere.org>") {
		t.Errorf("missing Return-Path:\n%s", text)
	}
	if !strings.Contains(text, "Received: from client.test (127.0.0.1)") ||
		!strings.Contains(text, "by mail.example.com (Kavira) with ESMTP") {
		t.Errorf("bad Received header:\n%s", text)
	}
	if !strings.Contains(text, "for <admin@example.com>") {
		t.Errorf("missing for clause:\n%s", text)
	}
	if !strings.Contains(text, "hello") {
		t.Errorf("missing body:\n%s", text)
	}
}

func TestRelayDenied(t *testing.T) {
	addr := testServer(t, t.TempDir(), nil)
	c := dial(t, addr)
	c.expect("220")
	c.send("EHLO spam.test")
	c.expect("250")
	c.send("MAIL FROM:<a@b.org>")
	c.expect("250")
	c.send("RCPT TO:<victim@external.org>")
	c.expect("554")
}

func TestUnknownUserRejected(t *testing.T) {
	addr := testServer(t, t.TempDir(), nil)
	c := dial(t, addr)
	c.expect("220")
	c.send("EHLO x.test")
	c.expect("250")
	c.send("MAIL FROM:<a@b.org>")
	c.expect("250")
	c.send("RCPT TO:<ghost@example.com>")
	c.expect("550")
}

func TestVrfyExpnDisabled(t *testing.T) {
	addr := testServer(t, t.TempDir(), nil)
	c := dial(t, addr)
	c.expect("220")
	c.send("VRFY admin")
	c.expect("502")
	c.send("EXPN list")
	c.expect("502")
	c.send("AUTH LOGIN")
	c.expect("503")
}

func TestCommandSequenceEnforced(t *testing.T) {
	addr := testServer(t, t.TempDir(), nil)
	c := dial(t, addr)
	c.expect("220")
	c.send("MAIL FROM:<a@b.org>")
	c.expect("503") // no EHLO yet
	c.send("EHLO x.test")
	c.expect("250")
	c.send("RCPT TO:<admin@example.com>")
	c.expect("503") // no MAIL yet
	c.send("DATA")
	c.expect("503") // no RCPT yet
}

func TestSizeLimits(t *testing.T) {
	addr := testServer(t, t.TempDir(), nil)
	c := dial(t, addr)
	c.expect("220")
	c.send("EHLO x.test")
	c.expect("250")
	c.send("MAIL FROM:<a@b.org> SIZE=999999999")
	c.expect("552")
	// Oversized DATA payload.
	c.send("MAIL FROM:<a@b.org>")
	c.expect("250")
	c.send("RCPT TO:<admin@example.com>")
	c.expect("250")
	c.send("DATA")
	c.expect("354")
	big := strings.Repeat("x", 70*1024)
	c.send(big + "\r\n.")
	c.expect("552")
	// Channel stays usable afterwards.
	c.send("NOOP")
	c.expect("250")
}

func TestPostmasterAccepted(t *testing.T) {
	root := t.TempDir()
	addr := testServer(t, root, nil)
	c := dial(t, addr)
	c.expect("220")
	c.send("EHLO x.test")
	c.expect("250")
	c.send("MAIL FROM:<a@b.org>")
	c.expect("250")
	c.send("RCPT TO:<postmaster>")
	c.expect("250")
}

func TestMaxRecipients(t *testing.T) {
	addr := testServer(t, t.TempDir(), nil)
	c := dial(t, addr)
	c.expect("220")
	c.send("EHLO x.test")
	c.expect("250")
	c.send("MAIL FROM:<a@b.org>")
	c.expect("250")
	for i := 0; i < 3; i++ {
		c.send("RCPT TO:<admin@example.com>")
		c.expect("250")
	}
	c.send("RCPT TO:<admin@example.com>")
	c.expect("452")
}

func TestConnectionRateLimit(t *testing.T) {
	addr := testServer(t, t.TempDir(), func(s *Settings) {
		s.Limits = ratelimit.NewInbound(1, 100, 100)
	})
	c1 := dial(t, addr)
	c1.expect("220")
	c2 := dial(t, addr)
	c2.expect("421")
}

func TestMessageRateLimitClosesChannel(t *testing.T) {
	root := t.TempDir()
	addr := testServer(t, root, func(s *Settings) {
		s.Limits = ratelimit.NewInbound(100, 1, 100)
	})
	c := dial(t, addr)
	c.expect("220")
	c.send("EHLO x.test")
	c.expect("250")
	for i := 0; i < 2; i++ {
		c.send("MAIL FROM:<a@b.org>")
		c.expect("250")
		c.send("RCPT TO:<admin@example.com>")
		c.expect("250")
		c.send("DATA")
		if i == 0 {
			c.expect("354")
			c.send("m\r\n.")
			c.expect("250")
		} else {
			c.expect("421")
		}
	}
}

func TestStartTLS(t *testing.T) {
	root := t.TempDir()
	tlsConf := testTLSConfig(t)
	addr := testServer(t, root, func(s *Settings) { s.TLS = tlsConf })

	c := dial(t, addr)
	c.expect("220")
	c.send("EHLO x.test")
	if caps := c.expect("250"); !strings.Contains(caps, "STARTTLS") {
		t.Fatalf("STARTTLS not advertised: %q", caps)
	}
	c.send("STARTTLS")
	c.expect("220")

	tconn := stdtls.Client(c.conn, &stdtls.Config{InsecureSkipVerify: true})
	if err := tconn.Handshake(); err != nil {
		t.Fatal(err)
	}
	tc := &client{t: t, conn: tconn, r: bufio.NewReader(tconn)}
	tc.send("EHLO x.test")
	if caps := tc.expect("250"); strings.Contains(caps, "STARTTLS") {
		t.Error("STARTTLS still advertised inside TLS")
	}
	tc.send("MAIL FROM:<a@b.org>")
	tc.expect("250")
	tc.send("RCPT TO:<admin@example.com>")
	tc.expect("250")
	tc.send("DATA")
	tc.expect("354")
	tc.send("secure\r\n.")
	tc.expect("250")

	ents, err := os.ReadDir(filepath.Join(root, "admin", "new"))
	if err != nil || len(ents) != 1 {
		t.Fatalf("want 1 message, got %v (%v)", ents, err)
	}
	msg, _ := os.ReadFile(filepath.Join(root, "admin", "new", ents[0].Name()))
	if !strings.Contains(string(msg), "with ESMTPS") {
		t.Errorf("Received header should say ESMTPS:\n%s", msg)
	}
}

// testTLSConfig builds a self-signed server config.
func testTLSConfig(t *testing.T) *stdtls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mail.example.com"},
		DNSNames:     []string{"mail.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &stdtls.Config{
		MinVersion:   stdtls.VersionTLS12,
		Certificates: []stdtls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	}
}
