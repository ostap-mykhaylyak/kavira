// Package logging provides the JSON log stream of kavira.
//
// Observability is reading log files: no dashboard, no rotation logic
// in the binary. Rotation is delegated to logrotate, which sends
// SIGHUP; the daemon then calls Reopen. Every line is JSON (slog),
// unbuffered, so a diagnostic line is on disk the instant it is
// written. High-volume protocol streams may become buffered in later
// milestones; the service stream stays unbuffered by design.
package logging

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

// reopenFile is an *os.File that can be reopened in place (logrotate
// hook). Writes are serialized with a mutex so a reopen never races a
// log line.
type reopenFile struct {
	mu   sync.Mutex
	path string
	f    *os.File
}

func openFile(path string) (*reopenFile, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, err
	}
	return &reopenFile{path: path, f: f}, nil
}

func (r *reopenFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Write(p)
}

func (r *reopenFile) Reopen() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	r.f.Close()
	r.f = f
	return nil
}

func (r *reopenFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}

// Logs bundles the log streams of the daemon.
type Logs struct {
	// Service is the daemon lifecycle and security stream.
	Service *slog.Logger

	svc *reopenFile
}

// Open creates dir if needed and opens the service stream inside it.
func Open(dir string) (*Logs, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	svc, err := openFile(filepath.Join(dir, "kavira.log"))
	if err != nil {
		return nil, err
	}
	return &Logs{
		Service: slog.New(slog.NewJSONHandler(svc, nil)),
		svc:     svc,
	}, nil
}

// OpenWriter builds Logs on an arbitrary writer (tests, foreground).
func OpenWriter(w io.Writer) *Logs {
	return &Logs{Service: slog.New(slog.NewJSONHandler(w, nil))}
}

// Reopen closes and reopens every file stream (logrotate via SIGHUP).
func (l *Logs) Reopen() error {
	if l.svc == nil {
		return nil
	}
	return l.svc.Reopen()
}

// Close closes every file stream.
func (l *Logs) Close() error {
	if l.svc == nil {
		return nil
	}
	return l.svc.Close()
}
