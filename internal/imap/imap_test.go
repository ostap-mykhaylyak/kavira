package imap

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

// testServer starts an implicit-TLS IMAP server over a Maildir root.
func testServer(t *testing.T, root string) string {
	t.Helper()
	srv := New(Settings{
		Hostname: "mail.example.com", ImplicitTLS: true, MaxSize: 1 << 20,
	}, Backend{
		Authenticate: func(email, password, ip string) (string, error) {
			if email == "admin@example.com" && password == "pw" {
				return root, nil
			}
			return "", errors.New("invalid credentials")
		},
	}, 8, slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))

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
	n    int
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
	c.readLine() // greeting
	return c
}

func (c *client) readLine() string {
	c.t.Helper()
	line, err := c.r.ReadString('\n')
	if err != nil {
		c.t.Fatalf("read: %v", err)
	}
	return strings.TrimRight(line, "\r\n")
}

// do sends a command and collects the response up to its tagged line.
func (c *client) do(cmd string) (untagged []string, tagged string) {
	c.t.Helper()
	c.n++
	tag := fmt.Sprintf("a%03d", c.n)
	fmt.Fprintf(c.conn, "%s %s\r\n", tag, cmd)
	for {
		line := c.readLine()
		if strings.HasPrefix(line, tag+" ") {
			return untagged, strings.TrimPrefix(line, tag+" ")
		}
		untagged = append(untagged, line)
	}
}

// ok runs a command and requires an OK completion.
func (c *client) ok(cmd string) []string {
	c.t.Helper()
	untagged, tagged := c.do(cmd)
	if !strings.HasPrefix(tagged, "OK") {
		c.t.Fatalf("%q -> %q, want OK", cmd, tagged)
	}
	return untagged
}

func (c *client) login() {
	c.t.Helper()
	c.ok(`LOGIN admin@example.com pw`)
}

func seed(t *testing.T, root string, subjects ...string) {
	t.Helper()
	for _, s := range subjects {
		msg := fmt.Sprintf("From: sender@remote.org\r\nTo: admin@example.com\r\nSubject: %s\r\n"+
			"Date: Mon, 06 Jul 2026 10:00:00 +0200\r\nMessage-ID: <%s@remote.org>\r\n\r\nCorpo di %s.\r\n", s, s, s)
		if _, err := maildir.Deliver(root, []byte(msg), -1, -1); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestLoginAndSelect(t *testing.T) {
	root := t.TempDir()
	seed(t, root, "uno", "due", "tre")
	c := dial(t, testServer(t, root))

	if _, tagged := c.do(`LOGIN admin@example.com wrong`); !strings.HasPrefix(tagged, "NO") {
		t.Fatalf("bad password -> %q, want NO", tagged)
	}
	c.login()

	untagged := c.ok("SELECT INBOX")
	joined := strings.Join(untagged, "\n")
	for _, want := range []string{"* 3 EXISTS", "* 3 RECENT", "UIDVALIDITY", "UIDNEXT", `\Seen`} {
		if !strings.Contains(joined, want) {
			t.Errorf("SELECT response missing %q:\n%s", want, joined)
		}
	}
}

func TestLoginRefusedWithoutTLS(t *testing.T) {
	root := t.TempDir()
	srv := New(Settings{Hostname: "mail.example.com", TLS: testTLSConfig(t), MaxSize: 1 << 20},
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
	greeting := c.readLine()
	if !strings.Contains(greeting, "LOGINDISABLED") {
		t.Errorf("plaintext greeting must advertise LOGINDISABLED: %q", greeting)
	}
	if !strings.Contains(greeting, "STARTTLS") {
		t.Errorf("greeting should offer STARTTLS: %q", greeting)
	}
	_, tagged := c.do("LOGIN admin@example.com pw")
	if !strings.HasPrefix(tagged, "NO") {
		t.Fatalf("LOGIN on plaintext -> %q, want NO", tagged)
	}
}

func TestFetchFlagsEnvelopeAndBody(t *testing.T) {
	root := t.TempDir()
	seed(t, root, "ciao")
	c := dial(t, testServer(t, root))
	c.login()
	c.ok("SELECT INBOX")

	untagged := c.ok("FETCH 1 (FLAGS RFC822.SIZE ENVELOPE)")
	joined := strings.Join(untagged, "\n")
	if !strings.Contains(joined, `\Recent`) {
		t.Errorf("fresh message should be \\Recent:\n%s", joined)
	}
	if !strings.Contains(joined, `"ciao"`) {
		t.Errorf("ENVELOPE should carry the subject:\n%s", joined)
	}
	if !strings.Contains(joined, `"sender" "remote.org"`) {
		t.Errorf("ENVELOPE should carry the From address:\n%s", joined)
	}

	// BODY.PEEK must not set \Seen.
	c.ok("FETCH 1 BODY.PEEK[HEADER]")
	untagged = c.ok("FETCH 1 FLAGS")
	if strings.Contains(strings.Join(untagged, "\n"), `\Seen`) {
		t.Error("BODY.PEEK must not mark the message \\Seen")
	}

	// A plain BODY[] fetch does set it.
	untagged = c.ok("FETCH 1 BODY[]")
	if !strings.Contains(strings.Join(untagged, "\n"), "Corpo di ciao") {
		t.Errorf("BODY[] should return the message:\n%s", strings.Join(untagged, "\n"))
	}
	untagged = c.ok("FETCH 1 FLAGS")
	if !strings.Contains(strings.Join(untagged, "\n"), `\Seen`) {
		t.Error("BODY[] must mark the message \\Seen")
	}
}

func TestFetchHeaderFields(t *testing.T) {
	root := t.TempDir()
	seed(t, root, "test")
	c := dial(t, testServer(t, root))
	c.login()
	c.ok("SELECT INBOX")

	untagged := c.ok("FETCH 1 BODY.PEEK[HEADER.FIELDS (SUBJECT FROM)]")
	joined := strings.Join(untagged, "\n")
	if !strings.Contains(joined, "Subject: test") || !strings.Contains(joined, "From: sender@remote.org") {
		t.Errorf("requested fields missing:\n%s", joined)
	}
	if strings.Contains(joined, "Message-ID:") {
		t.Errorf("unrequested field leaked:\n%s", joined)
	}
}

func TestUIDFetchAlwaysReportsUID(t *testing.T) {
	root := t.TempDir()
	seed(t, root, "a", "b")
	c := dial(t, testServer(t, root))
	c.login()
	c.ok("SELECT INBOX")

	untagged := c.ok("UID FETCH 1:* FLAGS")
	joined := strings.Join(untagged, "\n")
	if !strings.Contains(joined, "UID 1") || !strings.Contains(joined, "UID 2") {
		t.Errorf("UID FETCH must include UIDs:\n%s", joined)
	}
}

func TestStoreFlags(t *testing.T) {
	root := t.TempDir()
	seed(t, root, "a", "b", "c")
	c := dial(t, testServer(t, root))
	c.login()
	c.ok("SELECT INBOX")

	untagged := c.ok(`STORE 1 +FLAGS (\Seen \Flagged)`)
	joined := strings.Join(untagged, "\n")
	if !strings.Contains(joined, `\Seen`) || !strings.Contains(joined, `\Flagged`) {
		t.Errorf("STORE response:\n%s", joined)
	}
	untagged = c.ok(`STORE 1 -FLAGS (\Flagged)`)
	if strings.Contains(strings.Join(untagged, "\n"), `\Flagged`) {
		t.Errorf("-FLAGS did not remove:\n%s", strings.Join(untagged, "\n"))
	}
	// .SILENT suppresses the untagged response.
	untagged = c.ok(`STORE 2 +FLAGS.SILENT (\Seen)`)
	if len(untagged) != 0 {
		t.Errorf(".SILENT must not emit FETCH responses: %v", untagged)
	}
	// The flag persisted anyway.
	untagged = c.ok("FETCH 2 FLAGS")
	if !strings.Contains(strings.Join(untagged, "\n"), `\Seen`) {
		t.Error(".SILENT must still apply the flag")
	}
}

func TestExpunge(t *testing.T) {
	root := t.TempDir()
	seed(t, root, "a", "b", "c")
	c := dial(t, testServer(t, root))
	c.login()
	c.ok("SELECT INBOX")

	c.ok(`STORE 2 +FLAGS (\Deleted)`)
	untagged := c.ok("EXPUNGE")
	if !strings.Contains(strings.Join(untagged, "\n"), "* 2 EXPUNGE") {
		t.Errorf("EXPUNGE response:\n%s", strings.Join(untagged, "\n"))
	}
	untagged = c.ok("FETCH 1:* FLAGS")
	if n := strings.Count(strings.Join(untagged, "\n"), "FETCH"); n != 2 {
		t.Errorf("want 2 messages after expunge, got %d", n)
	}
}

func TestSearch(t *testing.T) {
	root := t.TempDir()
	seed(t, root, "fattura", "preventivo", "fattura-bis")
	c := dial(t, testServer(t, root))
	c.login()
	c.ok("SELECT INBOX")

	untagged := c.ok("SEARCH SUBJECT fattura")
	line := strings.Join(untagged, "\n")
	if !strings.Contains(line, "* SEARCH 1 3") {
		t.Errorf("SEARCH SUBJECT = %q, want messages 1 and 3", line)
	}
	untagged = c.ok("SEARCH UNSEEN")
	if !strings.Contains(strings.Join(untagged, "\n"), "* SEARCH 1 2 3") {
		t.Errorf("SEARCH UNSEEN = %q", strings.Join(untagged, "\n"))
	}
	c.ok(`STORE 1 +FLAGS (\Seen)`)
	untagged = c.ok("SEARCH SEEN")
	if !strings.Contains(strings.Join(untagged, "\n"), "* SEARCH 1") {
		t.Errorf("SEARCH SEEN = %q", strings.Join(untagged, "\n"))
	}
	untagged = c.ok("SEARCH BODY preventivo")
	if !strings.Contains(strings.Join(untagged, "\n"), "* SEARCH 2") {
		t.Errorf("SEARCH BODY = %q", strings.Join(untagged, "\n"))
	}
	// No match yields a bare untagged SEARCH.
	untagged = c.ok("SEARCH SUBJECT inesistente")
	if strings.TrimSpace(strings.Join(untagged, "\n")) != "* SEARCH" {
		t.Errorf("empty SEARCH = %q", strings.Join(untagged, "\n"))
	}
	// UID SEARCH reports UIDs.
	untagged = c.ok("UID SEARCH SUBJECT fattura")
	if !strings.Contains(strings.Join(untagged, "\n"), "* SEARCH 1 3") {
		t.Errorf("UID SEARCH = %q", strings.Join(untagged, "\n"))
	}
}

func TestCreateListCopyMove(t *testing.T) {
	root := t.TempDir()
	seed(t, root, "a", "b")
	c := dial(t, testServer(t, root))
	c.login()

	c.ok(`CREATE Archivio`)
	untagged := c.ok(`LIST "" "*"`)
	joined := strings.Join(untagged, "\n")
	if !strings.Contains(joined, `"INBOX"`) || !strings.Contains(joined, `"Archivio"`) {
		t.Errorf("LIST:\n%s", joined)
	}

	c.ok("SELECT INBOX")
	c.ok("COPY 1 Archivio")
	untagged = c.ok(`STATUS Archivio (MESSAGES)`)
	if !strings.Contains(strings.Join(untagged, "\n"), "MESSAGES 1") {
		t.Errorf("STATUS after COPY: %v", untagged)
	}
	// The source keeps the message.
	untagged = c.ok(`STATUS INBOX (MESSAGES)`)
	if !strings.Contains(strings.Join(untagged, "\n"), "MESSAGES 2") {
		t.Errorf("COPY must not remove the source: %v", untagged)
	}

	// MOVE removes it.
	untagged = c.ok("MOVE 1 Archivio")
	if !strings.Contains(strings.Join(untagged, "\n"), "EXPUNGE") {
		t.Errorf("MOVE should emit EXPUNGE: %v", untagged)
	}
	untagged = c.ok(`STATUS INBOX (MESSAGES)`)
	if !strings.Contains(strings.Join(untagged, "\n"), "MESSAGES 1") {
		t.Errorf("STATUS after MOVE: %v", untagged)
	}
	untagged = c.ok(`STATUS Archivio (MESSAGES)`)
	if !strings.Contains(strings.Join(untagged, "\n"), "MESSAGES 2") {
		t.Errorf("MOVE destination: %v", untagged)
	}
}

func TestAppendWithLiteral(t *testing.T) {
	root := t.TempDir()
	addr := testServer(t, root)
	c := dial(t, addr)
	c.login()

	msg := "From: me@example.com\r\nSubject: bozza\r\n\r\ntesto\r\n"
	c.n++
	tag := fmt.Sprintf("a%03d", c.n)
	fmt.Fprintf(c.conn, "%s APPEND INBOX (\\Seen) {%d}\r\n", tag, len(msg))
	if line := c.readLine(); !strings.HasPrefix(line, "+") {
		t.Fatalf("want continuation, got %q", line)
	}
	fmt.Fprint(c.conn, msg+"\r\n")
	for {
		line := c.readLine()
		if strings.HasPrefix(line, tag+" ") {
			if !strings.Contains(line, "OK") {
				t.Fatalf("APPEND -> %q", line)
			}
			if !strings.Contains(line, "APPENDUID") {
				t.Errorf("APPEND should report APPENDUID: %q", line)
			}
			break
		}
	}
	c.ok("SELECT INBOX")
	untagged := c.ok("FETCH 1 (FLAGS BODY.PEEK[])")
	joined := strings.Join(untagged, "\n")
	if !strings.Contains(joined, "bozza") {
		t.Errorf("appended message not readable:\n%s", joined)
	}
	if !strings.Contains(joined, `\Seen`) {
		t.Errorf("appended flags lost:\n%s", joined)
	}
}

func TestSelectedStateRequired(t *testing.T) {
	root := t.TempDir()
	c := dial(t, testServer(t, root))
	if _, tagged := c.do("FETCH 1 FLAGS"); !strings.HasPrefix(tagged, "NO") {
		t.Errorf("FETCH before login -> %q", tagged)
	}
	c.login()
	if _, tagged := c.do("FETCH 1 FLAGS"); !strings.HasPrefix(tagged, "NO") {
		t.Errorf("FETCH without SELECT -> %q", tagged)
	}
}

func TestExamineIsReadOnly(t *testing.T) {
	root := t.TempDir()
	seed(t, root, "a")
	c := dial(t, testServer(t, root))
	c.login()

	_, tagged := c.do("EXAMINE INBOX")
	if !strings.Contains(tagged, "READ-ONLY") {
		t.Errorf("EXAMINE -> %q, want READ-ONLY", tagged)
	}
	if _, tagged := c.do(`STORE 1 +FLAGS (\Seen)`); !strings.HasPrefix(tagged, "NO") {
		t.Errorf("STORE in EXAMINE -> %q, want NO", tagged)
	}
}

func TestIdleReportsNewMail(t *testing.T) {
	root := t.TempDir()
	seed(t, root, "prima")
	c := dial(t, testServer(t, root))
	c.login()
	c.ok("SELECT INBOX")

	c.n++
	tag := fmt.Sprintf("a%03d", c.n)
	fmt.Fprintf(c.conn, "%s IDLE\r\n", tag)
	if line := c.readLine(); !strings.HasPrefix(line, "+") {
		t.Fatalf("IDLE -> %q, want continuation", line)
	}

	// Deliver while the client is parked.
	seed(t, root, "durante-idle")

	c.conn.SetDeadline(time.Now().Add(20 * time.Second))
	got := ""
	for i := 0; i < 5; i++ {
		line := c.readLine()
		got += line + "\n"
		if strings.Contains(line, "EXISTS") {
			break
		}
	}
	if !strings.Contains(got, "* 2 EXISTS") {
		t.Fatalf("IDLE did not push the new message:\n%s", got)
	}

	fmt.Fprint(c.conn, "DONE\r\n")
	for {
		line := c.readLine()
		if strings.HasPrefix(line, tag+" ") {
			if !strings.Contains(line, "OK") {
				t.Errorf("IDLE termination -> %q", line)
			}
			return
		}
	}
}

func TestSequenceSetParsing(t *testing.T) {
	cases := []struct {
		spec  string
		n, mx uint32
		want  bool
	}{
		{"1", 1, 10, true},
		{"1", 2, 10, false},
		{"2:4", 3, 10, true},
		{"2:4", 5, 10, false},
		{"1,3,5", 3, 10, true},
		{"1,3,5", 4, 10, false},
		{"5:*", 9, 10, true},
		{"5:*", 4, 10, false},
		{"*", 10, 10, true},
		{"4:2", 3, 10, true}, // reversed ranges are legal
	}
	for _, c := range cases {
		set, err := parseSeqSet(c.spec)
		if err != nil {
			t.Fatalf("parse %q: %v", c.spec, err)
		}
		if got := set.contains(c.n, c.mx); got != c.want {
			t.Errorf("%q contains(%d, max=%d) = %v, want %v", c.spec, c.n, c.mx, got, c.want)
		}
	}
	if _, err := parseSeqSet("0"); err == nil {
		t.Error("0 is not a valid message number")
	}
	if _, err := parseSeqSet("abc"); err == nil {
		t.Error("garbage must not parse")
	}
}

func TestWildcardMatching(t *testing.T) {
	cases := []struct {
		pat, name string
		want      bool
	}{
		{"*", "INBOX", true},
		{"*", "Lavoro.Clienti", true},
		{"%", "INBOX", true},
		{"%", "Lavoro.Clienti", false}, // % stops at the delimiter
		{"Lavoro.%", "Lavoro.Clienti", true},
		{"Lavoro.*", "Lavoro.Clienti.2026", true},
		{"Arch*", "Archivio", true},
		{"Arch*", "INBOX", false},
	}
	for _, c := range cases {
		if got := matchPattern(c.pat, c.name); got != c.want {
			t.Errorf("matchPattern(%q, %q) = %v, want %v", c.pat, c.name, got, c.want)
		}
	}
}
