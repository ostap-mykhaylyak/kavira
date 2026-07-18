package imap

import (
	stdtls "crypto/tls"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Settings are the per-reload tunables of the IMAP server.
type Settings struct {
	Hostname string
	// TLS enables STARTTLS when non-nil.
	TLS *stdtls.Config
	// ImplicitTLS marks the listener as already encrypted (port 993).
	ImplicitTLS bool
	// MaxSize caps an APPENDed message.
	MaxSize int64
}

// Backend supplies authentication and mailbox location. Both are
// looked up per call, so a SIGHUP reload is picked up immediately.
type Backend struct {
	// Authenticate verifies credentials and returns the account's
	// Maildir root.
	Authenticate func(email, password, ip string) (maildir string, err error)
}

// Server accepts IMAP connections.
type Server struct {
	set     atomic.Pointer[Settings]
	backend Backend
	log     *slog.Logger

	sem    chan struct{}
	wg     sync.WaitGroup
	ln     net.Listener
	closed atomic.Bool
}

// New builds an IMAP Server. workers caps concurrent sessions.
func New(set Settings, backend Backend, workers int, log *slog.Logger) *Server {
	s := &Server{backend: backend, log: log, sem: make(chan struct{}, workers)}
	s.set.Store(&set)
	return s
}

// Update swaps the runtime settings (SIGHUP reload).
func (s *Server) Update(set Settings) { s.set.Store(&set) }

// Serve accepts connections until Shutdown.
func (s *Server) Serve(ln net.Listener) error {
	s.ln = ln
	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.closed.Load() {
				return nil
			}
			return err
		}
		select {
		case s.sem <- struct{}{}:
		default:
			conn.Write([]byte("* BYE server busy, try again later\r\n"))
			conn.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer func() { <-s.sem; s.wg.Done() }()
			newSession(s, conn).run()
		}()
	}
}

// Shutdown stops accepting and drains sessions up to timeout.
func (s *Server) Shutdown(timeout time.Duration) {
	s.closed.Store(true)
	if s.ln != nil {
		s.ln.Close()
	}
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(timeout):
		s.log.Warn("shutdown timeout, abandoning open imap sessions")
	}
}

func remoteIP(c net.Conn) string {
	if host, _, err := net.SplitHostPort(c.RemoteAddr().String()); err == nil {
		return host
	}
	return c.RemoteAddr().String()
}
