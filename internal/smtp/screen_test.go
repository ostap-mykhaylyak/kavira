package smtp

import (
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ostap-mykhaylyak/kavira/internal/maildir"
	"github.com/ostap-mykhaylyak/kavira/internal/storage"
)

// screenServer starts an inbound server whose Screen hook returns a
// scripted verdict, and reports what raw bytes Screen was handed.
func screenServer(t *testing.T, mailRoot string, verdict ScreenResult) (addr string, seen *[]byte) {
	t.Helper()
	var captured []byte
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
		Screen: func(ip, helo, from string, data []byte) ScreenResult {
			captured = append([]byte(nil), data...)
			return verdict
		},
	}
	srv := New(Settings{
		Hostname: "mail.example.com", MaxSize: 64 * 1024, MaxRecipients: 3,
	}, backend, 4, slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Shutdown(2 * time.Second) })
	return ln.Addr().String(), &captured
}

// sendOne runs a one-message transaction and returns the DATA reply.
func sendOne(t *testing.T, addr string) string {
	t.Helper()
	c := dial(t, addr)
	c.expect("220")
	c.send("EHLO mx.sender.org")
	c.expect("250")
	c.send("MAIL FROM:<news@sender.org>")
	c.expect("250")
	c.send("RCPT TO:<admin@example.com>")
	c.expect("250")
	c.send("DATA")
	c.expect("354")
	c.send("From: news@sender.org\r\nSubject: x\r\n\r\ncorpo\r\n.")
	// Read whatever the server answers to the message.
	var full strings.Builder
	for {
		line, err := c.r.ReadString('\n')
		if err != nil {
			t.Fatalf("read: %v (so far %q)", err, full.String())
		}
		full.WriteString(line)
		if len(line) >= 4 && line[3] == ' ' {
			return full.String()
		}
	}
}

func TestScreenRejectAnswers550(t *testing.T) {
	root := t.TempDir()
	addr, _ := screenServer(t, root, ScreenResult{
		Action: ScreenReject,
		Reason: "DMARC policy reject for sender.org",
	})
	reply := sendOne(t, addr)
	if !strings.HasPrefix(reply, "550") {
		t.Fatalf("reply = %q, want 550", reply)
	}
	if !strings.Contains(reply, "DMARC policy reject") {
		t.Errorf("reply should carry the reason: %q", reply)
	}
	if _, err := os.ReadDir(filepath.Join(root, "admin", "new")); err == nil {
		t.Error("rejected message must not be delivered")
	}
}

func TestScreenQuarantineGoesToSpamFolder(t *testing.T) {
	root := t.TempDir()
	addr, _ := screenServer(t, root, ScreenResult{
		Action:      ScreenQuarantine,
		Reason:      "DMARC policy quarantine for sender.org",
		AuthResults: "Authentication-Results: mail.example.com;\r\n\tdmarc=fail header.from=sender.org\r\n",
	})
	if reply := sendOne(t, addr); !strings.HasPrefix(reply, "250") {
		t.Fatalf("quarantine must still accept the message: %q", reply)
	}
	// Delivered into .Spam, not INBOX.
	if ents, err := os.ReadDir(filepath.Join(root, "admin", ".Spam", "new")); err != nil || len(ents) != 1 {
		t.Fatalf("want 1 message in .Spam: %v (%v)", ents, err)
	}
	if ents, err := os.ReadDir(filepath.Join(root, "admin", "new")); err == nil && len(ents) != 0 {
		t.Errorf("INBOX must stay empty, got %d", len(ents))
	}
}

func TestScreenSeesRawMessageAndHeaderOrder(t *testing.T) {
	root := t.TempDir()
	ar := "Authentication-Results: mail.example.com;\r\n\tspf=pass smtp.mailfrom=sender.org\r\n"
	addr, seen := screenServer(t, root, ScreenResult{AuthResults: ar})
	if reply := sendOne(t, addr); !strings.HasPrefix(reply, "250") {
		t.Fatalf("reply = %q", reply)
	}

	// Screen must receive the message exactly as sent: no locally
	// added header, or DKIM verification would break.
	raw := string(*seen)
	if strings.Contains(raw, "Received:") || strings.Contains(raw, "Authentication-Results:") {
		t.Errorf("Screen saw locally added headers:\n%s", raw)
	}
	if !strings.HasPrefix(raw, "From: news@sender.org") {
		t.Errorf("Screen input should start at the original headers:\n%s", raw)
	}

	ents, err := os.ReadDir(filepath.Join(root, "admin", "new"))
	if err != nil || len(ents) != 1 {
		t.Fatalf("want 1 delivered message: %v (%v)", ents, err)
	}
	msg, _ := os.ReadFile(filepath.Join(root, "admin", "new", ents[0].Name()))
	text := string(msg)

	iAR := strings.Index(text, "Authentication-Results:")
	iRcv := strings.Index(text, "Received:")
	iFrom := strings.Index(text, "From: news@sender.org")
	if iAR < 0 || iRcv < 0 || iFrom < 0 {
		t.Fatalf("missing headers:\n%s", text)
	}
	// Authentication-Results above our Received, both above the
	// original message headers.
	if !(iAR < iRcv && iRcv < iFrom) {
		t.Errorf("header order wrong (AR=%d Received=%d From=%d):\n%s", iAR, iRcv, iFrom, text)
	}
}

func TestNoScreenHookLeavesMessageUnannotated(t *testing.T) {
	root := t.TempDir()
	addr := testServer(t, root, nil) // Screen is nil here
	if reply := sendOne(t, addr); !strings.HasPrefix(reply, "250") {
		t.Fatalf("reply = %q", reply)
	}
	ents, _ := os.ReadDir(filepath.Join(root, "admin", "new"))
	if len(ents) != 1 {
		t.Fatalf("want 1 message, got %d", len(ents))
	}
	msg, _ := os.ReadFile(filepath.Join(root, "admin", "new", ents[0].Name()))
	if strings.Contains(string(msg), "Authentication-Results:") {
		t.Errorf("no Screen hook must not stamp Authentication-Results:\n%s", msg)
	}
}
