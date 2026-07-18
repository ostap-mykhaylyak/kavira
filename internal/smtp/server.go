// Package smtp implements the inbound SMTP server (RFC 5321) for
// port 25: receiving mail addressed to the locally hosted domains.
//
// Anti open relay is structural, not a configuration option: on this
// listener a recipient is either a local mailbox or the transaction is
// refused. There is no code path that queues a message toward a
// foreign domain; authenticated relay arrives with submission (M2) on
// its own listeners.
//
// VRFY and EXPN are permanently disabled (user enumeration). The
// banner and the Received header expose only the configured public
// hostname, never an internal or container name.
package smtp

import (
	stdtls "crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ostap-mykhaylyak/kavira/internal/ratelimit"
	"github.com/ostap-mykhaylyak/kavira/internal/storage"
)

// Mode selects the personality of a listener.
type Mode int

const (
	// ModeInbound is port 25: unauthenticated MX reception for local
	// domains only. AUTH is refused, relay is structurally impossible.
	ModeInbound Mode = iota
	// ModeSubmission is 587/465: message submission by authenticated
	// users (RFC 6409). Relay to any domain, but only after AUTH over
	// TLS, and only with the sender identity of the authenticated
	// user.
	ModeSubmission
)

// Settings are the per-reload tunables of the server.
type Settings struct {
	Hostname      string
	MaxSize       int64
	MaxRecipients int
	Mode          Mode
	// ImplicitTLS marks sessions as TLS from byte one (port 465; the
	// listener itself is wrapped by the caller).
	ImplicitTLS bool
	// TLS enables STARTTLS when non-nil.
	TLS *stdtls.Config
	// Limits is the per-IP inbound rate limiter set; nil disables it.
	Limits *ratelimit.Inbound
	// OutLimits is the per-user outbound limiter set (submission);
	// nil disables it.
	OutLimits *ratelimit.Outbound
}

// ScreenAction is the verdict of the inbound authentication pipeline.
type ScreenAction int

const (
	ScreenAccept ScreenAction = iota
	ScreenQuarantine
	ScreenReject
)

// ScreenResult carries the verdict and the headers to stamp on the
// message.
type ScreenResult struct {
	Action      ScreenAction
	Reason      string
	AuthResults string
	// SpamHeader is the X-Spam-Status line, empty when not scored.
	SpamHeader string
}

// Backend answers the questions the protocol cannot: what is local
// and where mail ends up. Implementations read the current config on
// every call, so a SIGHUP reload is picked up per-transaction.
type Backend struct {
	// IsLocalDomain reports whether domain is hosted here.
	IsLocalDomain func(domain string) bool
	// Lookup resolves a local address to its mailbox.
	Lookup func(email string) (storage.Mailbox, bool)
	// Deliver stores the message into a mailbox: from is the envelope
	// sender (Return-Path), spam selects the quarantine folder.
	Deliver func(mb storage.Mailbox, from string, spam bool, msg []byte) error
	// Postmaster returns the address behind a bare RCPT
	// TO:<postmaster>, or "" when none is configured.
	Postmaster func() string
	// Authenticate verifies credentials (submission). A nil error
	// authenticates; auth.ErrLocked and auth.ErrInvalid map to reply
	// codes. Nil Authenticate disables AUTH entirely.
	Authenticate func(email, password, ip string) error
	// Enqueue stores an outbound message for a remote recipient
	// (submission relay path).
	Enqueue func(from, rcpt string, data []byte) error
	// Screen runs the inbound authentication pipeline (SPF, DKIM,
	// DMARC) on port 25. Nil disables screening. data is the raw
	// message exactly as received, before any locally added header.
	Screen func(ip, helo, from string, data []byte) ScreenResult
	// Sign adds the DKIM signature for the sender domain on
	// submission. Nil (or a domain without a key) sends unsigned.
	Sign func(fromDomain string, msg []byte) ([]byte, error)
	// MaySend gates outbound submission on the sender's reputation
	// and warm-up allowance. It returns a reason when sending is
	// refused. Nil disables the check.
	MaySend func(user, domain string) (ok bool, reason string)
	// Sent reports an accepted submission, so the reputation store
	// can count it against the daily warm-up cap. Nil disables it.
	Sent func(user, domain string)
}

// Server accepts inbound SMTP connections.
type Server struct {
	set     atomic.Pointer[Settings]
	backend Backend
	log     *slog.Logger

	sem    chan struct{} // caps concurrent sessions
	wg     sync.WaitGroup
	ln     net.Listener
	closed atomic.Bool
}

// New builds a Server. workers caps concurrent sessions for the whole
// server lifetime (listener-level; not changed by reload).
func New(set Settings, backend Backend, workers int, log *slog.Logger) *Server {
	s := &Server{backend: backend, log: log, sem: make(chan struct{}, workers)}
	s.set.Store(&set)
	return s
}

// Update swaps the runtime settings (SIGHUP reload). In-flight
// sessions finish with the settings they started with.
func (s *Server) Update(set Settings) { s.set.Store(&set) }

// Serve accepts connections on ln until Shutdown. It returns nil on
// clean shutdown.
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
		ip := remoteIP(conn)
		set := s.set.Load()

		if !set.Limits.ConnAllowed(ip) {
			s.log.Warn("connection rate limited",
				"event", "ratelimit", "protocol", "smtp", "ip", ip, "action", "reject_connection")
			fmt.Fprintf(conn, "421 4.7.0 %s too many connections, try again later\r\n", set.Hostname)
			conn.Close()
			continue
		}
		select {
		case s.sem <- struct{}{}:
		default:
			fmt.Fprintf(conn, "421 4.3.2 %s server busy, try again later\r\n", set.Hostname)
			conn.Close()
			continue
		}

		s.wg.Add(1)
		go func() {
			defer func() { <-s.sem; s.wg.Done() }()
			newSession(s, conn, ip).run()
		}()
	}
}

// Shutdown stops accepting and waits up to timeout for the running
// sessions to finish.
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
		s.log.Warn("shutdown timeout, abandoning open smtp sessions")
	}
}

// remoteIP extracts the bare IP of a connection.
func remoteIP(c net.Conn) string {
	if host, _, err := net.SplitHostPort(c.RemoteAddr().String()); err == nil {
		return host
	}
	return c.RemoteAddr().String()
}

// parsePath extracts the address from a MAIL/RCPT argument like
// "FROM:<a@b> SIZE=123". It returns the address (possibly empty for
// the null reverse-path) and the raw parameters.
func parsePath(arg, prefix string) (addr string, params []string, err error) {
	if len(arg) < len(prefix) || !strings.EqualFold(arg[:len(prefix)], prefix) {
		return "", nil, errors.New("syntax error")
	}
	rest := strings.TrimSpace(arg[len(prefix):])
	if !strings.HasPrefix(rest, "<") {
		return "", nil, errors.New("syntax error: missing <")
	}
	end := strings.IndexByte(rest, '>')
	if end < 0 {
		return "", nil, errors.New("syntax error: missing >")
	}
	addr = rest[1:end]
	// Strip an obsolete source route (@a,@b:user@domain).
	if i := strings.LastIndexByte(addr, ':'); i >= 0 && strings.HasPrefix(addr, "@") {
		addr = addr[i+1:]
	}
	if rest[end+1:] != "" {
		params = strings.Fields(rest[end+1:])
	}
	return addr, params, nil
}

// sizeParam extracts SIZE=n from ESMTP parameters, 0 when absent.
func sizeParam(params []string) (int64, error) {
	for _, p := range params {
		if v, ok := strings.CutPrefix(strings.ToUpper(p), "SIZE="); ok {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n < 0 {
				return 0, errors.New("invalid SIZE")
			}
			return n, nil
		}
	}
	return 0, nil
}

// sanitizeHelo makes a client-supplied HELO name safe to embed in a
// trace header.
func sanitizeHelo(h string) string {
	if len(h) > 255 {
		h = h[:255]
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '.', r == '-', r == ':', r == '[', r == ']', r == '_':
			return r
		}
		return '?'
	}, h)
}
