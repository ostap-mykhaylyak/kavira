// Package maildir writes messages in standard Maildir format.
//
// Delivery follows the Maildir contract: the message is written and
// fsynced under tmp/ with a unique name, then renamed into new/ —
// readers never observe a partial message. Ownership (system-user
// mailboxes) is applied to both directories and messages; chown is
// skipped on non-Linux systems and for virtual mailboxes (uid < 0).
package maildir

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
)

// seq disambiguates deliveries within the same nanosecond and process.
var seq atomic.Uint64

// hostToken is the host part of a Maildir filename. It defaults to
// the machine name, but inside a container that is the container's
// own name, which must not be recorded anywhere: the daemon sets this
// to the configured public hostname at startup.
var hostToken atomic.Pointer[string]

// SetHostname overrides the host part of generated Maildir filenames.
func SetHostname(name string) {
	name = sanitizeHost(name)
	if name == "" {
		return
	}
	hostToken.Store(&name)
}

// host returns the token to embed in a filename.
func host() string {
	if p := hostToken.Load(); p != nil {
		return *p
	}
	h, _ := os.Hostname()
	if h = sanitizeHost(h); h != "" {
		return h
	}
	return "localhost"
}

// sanitizeHost strips the characters Maildir reserves inside a
// filename (':' separates the flags, '/' is a path separator).
func sanitizeHost(h string) string {
	return strings.NewReplacer(":", "-", "/", "-", "\\", "-", " ", "-").Replace(strings.TrimSpace(h))
}

// Deliver writes msg into the Maildir rooted at dir, creating the
// cur/new/tmp layout on first use. uid/gid < 0 means no ownership
// change. It returns the final path under new/.
func Deliver(dir string, msg []byte, uid, gid int) (string, error) {
	for _, sub := range []string{"", "tmp", "new", "cur"} {
		p := filepath.Join(dir, sub)
		if err := os.MkdirAll(p, 0o700); err != nil {
			return "", fmt.Errorf("maildir %s: %w", dir, err)
		}
		chown(p, uid, gid)
	}

	name := fmt.Sprintf("%d.M%dP%dQ%dR%x.%s",
		time.Now().Unix(), time.Now().Nanosecond()/1000, os.Getpid(),
		seq.Add(1), rand.Uint32(), host())

	tmp := filepath.Join(dir, "tmp", name)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("maildir %s: %w", dir, err)
	}
	if _, err := f.Write(msg); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return "", fmt.Errorf("maildir %s: %w", dir, err)
	}
	chown(tmp, uid, gid)

	final := filepath.Join(dir, "new", name)
	if err := os.Rename(tmp, final); err != nil {
		os.Remove(tmp)
		return "", fmt.Errorf("maildir %s: %w", dir, err)
	}
	return final, nil
}

// chown applies ownership where it makes sense; failures are ignored
// on purpose (delivery must not fail because a chown is not permitted
// in a test or development environment — the daemon runs as root in
// production).
func chown(path string, uid, gid int) {
	if uid < 0 || runtime.GOOS == "windows" {
		return
	}
	os.Chown(path, uid, gid)
}
