package pop3

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ostap-mykhaylyak/kavira/internal/maildir"
)

func testTLSConfig(t *testing.T) *stdtls.Config {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mail.example.com"},
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

func testServer(t *testing.T, root string) string {
	t.Helper()
	srv := New(Settings{Hostname: "mail.example.com", ImplicitTLS: true},
		Backend{Authenticate: func(email, password, ip string) (string, error) {
			if email == "admin@example.com" && password == "pw" {
				return root, nil
			}
			return "", errors.New("invalid credentials")
		}},
		8, slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(stdtls.NewListener(ln, testTLSConfig(t)))
	t.Cleanup(func() { srv.Shutdown(2 * time.Second) })
	return ln.Addr().String()
}

type client struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
}

func dial(t *testing.T, addr string) *client {
	t.Helper()
	conn, err := stdtls.Dial("tcp", addr, &stdtls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	c := &client{t: t, conn: conn, r: bufio.NewReader(conn)}
	c.line() // greeting
	return c
}

func (c *client) line() string {
	c.t.Helper()
	l, err := c.r.ReadString('\n')
	if err != nil {
		c.t.Fatalf("read: %v", err)
	}
	return strings.TrimRight(l, "\r\n")
}

// cmd sends a command and returns the status line.
func (c *client) cmd(s string) string {
	c.t.Helper()
	fmt.Fprintf(c.conn, "%s\r\n", s)
	return c.line()
}

// multi sends a command and collects a dot-terminated response.
func (c *client) multi(s string) (status string, body []string) {
	c.t.Helper()
	status = c.cmd(s)
	if !strings.HasPrefix(status, "+OK") {
		return status, nil
	}
	for {
		l := c.line()
		if l == "." {
			return status, body
		}
		body = append(body, l)
	}
}

func (c *client) login() {
	c.t.Helper()
	if r := c.cmd("USER admin@example.com"); !strings.HasPrefix(r, "+OK") {
		c.t.Fatalf("USER -> %q", r)
	}
	if r := c.cmd("PASS pw"); !strings.HasPrefix(r, "+OK") {
		c.t.Fatalf("PASS -> %q", r)
	}
}

func seed(t *testing.T, root string, bodies ...string) {
	t.Helper()
	for _, b := range bodies {
		msg := fmt.Sprintf("From: sender@remote.org\r\nSubject: %s\r\n\r\nCorpo %s.\r\nSeconda riga.\r\n", b, b)
		if _, err := maildir.Deliver(root, []byte(msg), -1, -1); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestStatListRetr(t *testing.T) {
	root := t.TempDir()
	seed(t, root, "uno", "due")
	c := dial(t, testServer(t, root))
	c.login()

	if r := c.cmd("STAT"); !strings.HasPrefix(r, "+OK 2 ") {
		t.Errorf("STAT -> %q", r)
	}
	_, body := c.multi("LIST")
	if len(body) != 2 || !strings.HasPrefix(body[0], "1 ") || !strings.HasPrefix(body[1], "2 ") {
		t.Errorf("LIST -> %v", body)
	}
	_, body = c.multi("RETR 1")
	joined := strings.Join(body, "\n")
	if !strings.Contains(joined, "Subject: uno") || !strings.Contains(joined, "Corpo uno.") {
		t.Errorf("RETR -> %v", body)
	}
}

func TestUidlStableAcrossSessions(t *testing.T) {
	root := t.TempDir()
	seed(t, root, "a", "b")
	addr := testServer(t, root)

	c := dial(t, addr)
	c.login()
	_, first := c.multi("UIDL")
	c.cmd("QUIT")

	c2 := dial(t, addr)
	c2.login()
	_, second := c2.multi("UIDL")
	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("UIDL listings: %v / %v", first, second)
	}
	for i := range first {
		if first[i] != second[i] {
			t.Errorf("UIDL changed between sessions: %q -> %q", first[i], second[i])
		}
	}
}

func TestTopDoesNotMarkSeenAndLimitsLines(t *testing.T) {
	root := t.TempDir()
	seed(t, root, "uno")
	addr := testServer(t, root)
	c := dial(t, addr)
	c.login()

	_, body := c.multi("TOP 1 1")
	joined := strings.Join(body, "\n")
	if !strings.Contains(joined, "Subject: uno") {
		t.Errorf("TOP must return the headers: %v", body)
	}
	if strings.Contains(joined, "Seconda riga") {
		t.Errorf("TOP 1 must stop after 1 body line: %v", body)
	}
	c.cmd("QUIT")

	// The message must still be unseen: TOP is only a preview.
	mb, err := maildir.OpenMailbox(root, maildir.Inbox)
	if err != nil {
		t.Fatal(err)
	}
	if mb.Messages()[0].Flags.Has(maildir.FlagSeen) {
		t.Error("TOP must not mark the message Seen")
	}
}

func TestRetrMarksSeen(t *testing.T) {
	root := t.TempDir()
	seed(t, root, "uno")
	c := dial(t, testServer(t, root))
	c.login()
	c.multi("RETR 1")
	c.cmd("QUIT")

	mb, _ := maildir.OpenMailbox(root, maildir.Inbox)
	if !mb.Messages()[0].Flags.Has(maildir.FlagSeen) {
		t.Error("RETR should mark the message Seen")
	}
}

func TestDeleteAppliesOnlyAtQuit(t *testing.T) {
	root := t.TempDir()
	seed(t, root, "uno", "due", "tre")
	addr := testServer(t, root)
	c := dial(t, addr)
	c.login()

	if r := c.cmd("DELE 2"); !strings.HasPrefix(r, "+OK") {
		t.Fatalf("DELE -> %q", r)
	}
	// Still on disk during the session.
	mb, _ := maildir.OpenMailbox(root, maildir.Inbox)
	if mb.Count() != 3 {
		t.Errorf("deletion must not apply before QUIT: %d", mb.Count())
	}
	// A deleted message is no longer retrievable in-session.
	if r := c.cmd("RETR 2"); !strings.HasPrefix(r, "-ERR") {
		t.Errorf("RETR of a deleted message -> %q", r)
	}
	if r := c.cmd("STAT"); !strings.HasPrefix(r, "+OK 2 ") {
		t.Errorf("STAT after DELE -> %q", r)
	}
	c.cmd("QUIT")

	mb2, _ := maildir.OpenMailbox(root, maildir.Inbox)
	if mb2.Count() != 2 {
		t.Fatalf("QUIT should have removed 1 message, count = %d", mb2.Count())
	}
	for _, m := range mb2.Messages() {
		data, _ := m.Read()
		if strings.Contains(string(data), "Subject: due") {
			t.Error("the wrong message survived")
		}
	}
}

func TestRsetUndoesDeletions(t *testing.T) {
	root := t.TempDir()
	seed(t, root, "uno", "due")
	addr := testServer(t, root)
	c := dial(t, addr)
	c.login()

	c.cmd("DELE 1")
	if r := c.cmd("RSET"); !strings.HasPrefix(r, "+OK") {
		t.Fatalf("RSET -> %q", r)
	}
	if r := c.cmd("STAT"); !strings.HasPrefix(r, "+OK 2 ") {
		t.Errorf("STAT after RSET -> %q", r)
	}
	c.cmd("QUIT")

	mb, _ := maildir.OpenMailbox(root, maildir.Inbox)
	if mb.Count() != 2 {
		t.Errorf("RSET should have cancelled the deletion: %d", mb.Count())
	}
}

func TestAuthRequiredAndBadPassword(t *testing.T) {
	root := t.TempDir()
	seed(t, root, "uno")
	c := dial(t, testServer(t, root))

	if r := c.cmd("STAT"); !strings.HasPrefix(r, "-ERR") {
		t.Errorf("STAT before login -> %q", r)
	}
	c.cmd("USER admin@example.com")
	if r := c.cmd("PASS sbagliata"); !strings.HasPrefix(r, "-ERR") {
		t.Errorf("bad password -> %q", r)
	}
	if r := c.cmd("STAT"); !strings.HasPrefix(r, "-ERR") {
		t.Errorf("STAT after failed login -> %q", r)
	}
}

func TestPlaintextRefusesCredentials(t *testing.T) {
	root := t.TempDir()
	srv := New(Settings{Hostname: "mail.example.com", TLS: testTLSConfig(t)},
		Backend{Authenticate: func(string, string, string) (string, error) { return root, nil }},
		4, slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Shutdown(2 * time.Second) })

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	c := &client{t: t, conn: conn, r: bufio.NewReader(conn)}
	c.line()

	if r := c.cmd("USER admin@example.com"); !strings.HasPrefix(r, "-ERR") {
		t.Errorf("USER on plaintext -> %q, want -ERR", r)
	}
	_, caps := c.multi("CAPA")
	if !strings.Contains(strings.Join(caps, " "), "STLS") {
		t.Errorf("CAPA should advertise STLS on plaintext: %v", caps)
	}
}

func TestDotStuffing(t *testing.T) {
	root := t.TempDir()
	// A body line starting with a dot must be stuffed on the wire.
	msg := "Subject: dots\r\n\r\n.una riga con punto\r\nnormale\r\n"
	if _, err := maildir.Deliver(root, []byte(msg), -1, -1); err != nil {
		t.Fatal(err)
	}
	c := dial(t, testServer(t, root))
	c.login()

	fmt.Fprint(c.conn, "RETR 1\r\n")
	c.line() // +OK
	var raw []string
	for {
		l := c.line()
		if l == "." {
			break
		}
		raw = append(raw, l)
	}
	joined := strings.Join(raw, "\n")
	if !strings.Contains(joined, "..una riga con punto") {
		t.Errorf("leading dot not stuffed:\n%s", joined)
	}
}
