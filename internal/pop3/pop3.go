// Package pop3 implements a POP3 server (RFC 1939) over the Maildir
// storage, with STLS (RFC 2595) on port 110 and implicit TLS on 995.
//
// POP3 is a download protocol: a session locks the INBOX view at
// login, numbers the messages 1..N for its duration, and applies
// deletions only at QUIT (the UPDATE state). Credentials are refused
// on a plaintext channel, exactly as in IMAP.
package pop3

import (
	"bufio"
	"crypto/md5"
	stdtls "crypto/tls"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ostap-mykhaylyak/kavira/internal/maildir"
)

const (
	sessionTimeout = 10 * time.Minute
	maxLine        = 1024
)

// Settings are the per-reload tunables.
type Settings struct {
	Hostname string
	// TLS enables STLS when non-nil.
	TLS *stdtls.Config
	// ImplicitTLS marks the listener as already encrypted (port 995).
	ImplicitTLS bool
}

// Backend supplies authentication and mailbox location.
type Backend struct {
	// Authenticate verifies credentials and returns the Maildir root.
	Authenticate func(email, password, ip string) (maildir string, err error)
}

// Server accepts POP3 connections.
type Server struct {
	set     atomic.Pointer[Settings]
	backend Backend
	log     *slog.Logger

	sem    chan struct{}
	wg     sync.WaitGroup
	ln     net.Listener
	closed atomic.Bool
}

// New builds a POP3 Server.
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
			conn.Write([]byte("-ERR server busy, try again later\r\n"))
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
		s.log.Warn("shutdown timeout, abandoning open pop3 sessions")
	}
}

// session is one POP3 connection.
type session struct {
	srv  *Server
	conn net.Conn
	r    *bufio.Reader
	w    *bufio.Writer
	ip   string

	tls   bool
	user  string
	root  string
	mbox  *maildir.Mailbox
	msgs  []*maildir.Message // the frozen 1..N view
	del   map[int]bool       // 1-based indices marked for deletion
	authd bool
}

func newSession(srv *Server, conn net.Conn) *session {
	host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	return &session{
		srv:  srv,
		conn: conn,
		r:    bufio.NewReaderSize(conn, 1024),
		w:    bufio.NewWriterSize(conn, 16*1024),
		ip:   host,
		tls:  srv.set.Load().ImplicitTLS,
		del:  map[int]bool{},
	}
}

func (s *session) set() *Settings { return s.srv.set.Load() }

func (s *session) ok(format string, args ...any) error {
	fmt.Fprintf(s.w, "+OK "+format+"\r\n", args...)
	return s.w.Flush()
}

func (s *session) err(format string, args ...any) error {
	fmt.Fprintf(s.w, "-ERR "+format+"\r\n", args...)
	return s.w.Flush()
}

func (s *session) readLine() (string, error) {
	s.conn.SetReadDeadline(time.Now().Add(sessionTimeout))
	line, err := s.r.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(line) > maxLine {
		return "", fmt.Errorf("line too long")
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func (s *session) run() {
	defer s.conn.Close()

	if err := s.ok("%s Kavira POP3 ready", s.set().Hostname); err != nil {
		return
	}
	for {
		line, err := s.readLine()
		if err != nil {
			return
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		cmd, arg, _ := strings.Cut(line, " ")
		arg = strings.TrimSpace(arg)

		switch strings.ToUpper(cmd) {
		case "CAPA":
			s.cmdCapa()
		case "STLS":
			if quit := s.cmdSTLS(); quit {
				return
			}
		case "USER":
			s.cmdUser(arg)
		case "PASS":
			s.cmdPass(arg)
		case "STAT":
			s.cmdStat()
		case "LIST":
			s.cmdList(arg)
		case "UIDL":
			s.cmdUidl(arg)
		case "RETR":
			s.cmdRetr(arg)
		case "TOP":
			s.cmdTop(arg)
		case "DELE":
			s.cmdDele(arg)
		case "RSET":
			s.cmdRset()
		case "NOOP":
			s.ok("")
		case "QUIT":
			s.cmdQuit()
			return
		default:
			s.err("unknown command")
		}
	}
}

func (s *session) cmdCapa() {
	s.w.WriteString("+OK capability list follows\r\n")
	s.w.WriteString("TOP\r\nUIDL\r\nUSER\r\nRESP-CODES\r\n")
	if !s.tls && s.set().TLS != nil {
		s.w.WriteString("STLS\r\n")
	}
	s.w.WriteString(".\r\n")
	s.w.Flush()
}

func (s *session) cmdSTLS() (quit bool) {
	set := s.set()
	if set.TLS == nil {
		s.err("TLS not available")
		return false
	}
	if s.tls {
		s.err("already in TLS")
		return false
	}
	if err := s.ok("begin TLS negotiation"); err != nil {
		return true
	}
	tlsConn := stdtls.Server(s.conn, set.TLS)
	s.conn.SetReadDeadline(time.Now().Add(time.Minute))
	if err := tlsConn.Handshake(); err != nil {
		s.srv.log.Warn("stls handshake failed",
			"event", "tls_error", "protocol", "pop3", "ip", s.ip, "error", err.Error())
		return true
	}
	s.conn = tlsConn
	s.r = bufio.NewReaderSize(tlsConn, 1024)
	s.w = bufio.NewWriterSize(tlsConn, 16*1024)
	s.tls = true
	// RFC 2595: the session resets to the authorization state.
	s.user, s.authd = "", false
	return false
}

func (s *session) cmdUser(arg string) {
	if !s.tls {
		s.err("[AUTH] STLS required before authentication")
		return
	}
	if arg == "" {
		s.err("USER needs a username")
		return
	}
	s.user = arg
	s.ok("send PASS")
}

func (s *session) cmdPass(arg string) {
	if !s.tls {
		s.err("[AUTH] STLS required before authentication")
		return
	}
	if s.user == "" {
		s.err("send USER first")
		return
	}
	root, err := s.srv.backend.Authenticate(s.user, arg, s.ip)
	if err != nil {
		s.srv.log.Warn("authentication failed",
			"event", "auth_failed", "protocol", "pop3", "ip", s.ip,
			"user", s.user, "action", "reject")
		s.user = ""
		s.err("[AUTH] authentication failed")
		return
	}
	mb, err := maildir.OpenMailbox(root, maildir.Inbox)
	if err != nil {
		s.err("cannot open mailbox")
		return
	}
	// Freeze the view: POP3 message numbers must stay stable for the
	// whole session, even if new mail arrives meanwhile.
	s.root, s.mbox, s.msgs, s.authd = root, mb, mb.Messages(), true
	s.srv.log.Info("authentication succeeded",
		"event", "auth_ok", "protocol", "pop3", "ip", s.ip, "user", s.user)
	s.ok("mailbox ready, %d messages (%d octets)", len(s.msgs), s.totalSize())
}

func (s *session) totalSize() int64 {
	var n int64
	for i, m := range s.msgs {
		if !s.del[i+1] {
			n += m.Size
		}
	}
	return n
}

// requireAuth guards the transaction-state commands.
func (s *session) requireAuth() bool {
	if !s.authd {
		s.err("not authenticated")
		return false
	}
	return true
}

// message resolves a 1-based message number that is not deleted.
func (s *session) message(arg string) (int, *maildir.Message, bool) {
	n, err := strconv.Atoi(arg)
	if err != nil || n < 1 || n > len(s.msgs) {
		s.err("no such message")
		return 0, nil, false
	}
	if s.del[n] {
		s.err("message %d already deleted", n)
		return 0, nil, false
	}
	return n, s.msgs[n-1], true
}

func (s *session) cmdStat() {
	if !s.requireAuth() {
		return
	}
	n := 0
	for i := range s.msgs {
		if !s.del[i+1] {
			n++
		}
	}
	s.ok("%d %d", n, s.totalSize())
}

func (s *session) cmdList(arg string) {
	if !s.requireAuth() {
		return
	}
	if arg != "" {
		n, m, ok := s.message(arg)
		if !ok {
			return
		}
		s.ok("%d %d", n, m.Size)
		return
	}
	s.w.WriteString(fmt.Sprintf("+OK %d messages\r\n", len(s.msgs)-len(s.del)))
	for i, m := range s.msgs {
		if s.del[i+1] {
			continue
		}
		fmt.Fprintf(s.w, "%d %d\r\n", i+1, m.Size)
	}
	s.w.WriteString(".\r\n")
	s.w.Flush()
}

// uidl derives a stable unique id. The Maildir base name is unique
// and permanent, but may contain characters POP3 forbids in a UIDL,
// so it is hashed.
func uidl(m *maildir.Message) string {
	sum := md5.Sum([]byte(maildir.BaseName(m.Name)))
	return hex.EncodeToString(sum[:])
}

func (s *session) cmdUidl(arg string) {
	if !s.requireAuth() {
		return
	}
	if arg != "" {
		n, m, ok := s.message(arg)
		if !ok {
			return
		}
		s.ok("%d %s", n, uidl(m))
		return
	}
	s.w.WriteString("+OK unique-id listing follows\r\n")
	for i, m := range s.msgs {
		if s.del[i+1] {
			continue
		}
		fmt.Fprintf(s.w, "%d %s\r\n", i+1, uidl(m))
	}
	s.w.WriteString(".\r\n")
	s.w.Flush()
}

// writeDotted writes a message body with dot-stuffing and the
// terminating ".".
func (s *session) writeDotted(data string, maxBodyLines int) {
	header, body, found := strings.Cut(data, "\r\n\r\n")
	if !found {
		header, body = data, ""
	}
	write := func(block string) {
		for _, line := range strings.Split(block, "\n") {
			line = strings.TrimSuffix(line, "\r")
			if strings.HasPrefix(line, ".") {
				s.w.WriteString(".") // dot-stuffing
			}
			s.w.WriteString(line)
			s.w.WriteString("\r\n")
		}
	}
	write(header)
	if maxBodyLines != 0 {
		s.w.WriteString("\r\n")
		lines := strings.Split(body, "\n")
		if maxBodyLines > 0 && len(lines) > maxBodyLines {
			lines = lines[:maxBodyLines]
		}
		write(strings.Join(lines, "\n"))
	}
	s.w.WriteString(".\r\n")
	s.w.Flush()
}

func (s *session) cmdRetr(arg string) {
	if !s.requireAuth() {
		return
	}
	_, m, ok := s.message(arg)
	if !ok {
		return
	}
	data, err := m.Read()
	if err != nil {
		s.err("cannot read message")
		return
	}
	// Retrieval marks the message Seen, as a mail client would.
	if !m.Flags.Has(maildir.FlagSeen) {
		s.mbox.SetFlags(m, m.Flags.Add(maildir.FlagSeen))
	}
	s.w.WriteString(fmt.Sprintf("+OK %d octets\r\n", len(data)))
	s.writeDotted(string(data), -1)
}

func (s *session) cmdTop(arg string) {
	if !s.requireAuth() {
		return
	}
	numStr, linesStr, ok := strings.Cut(arg, " ")
	if !ok {
		s.err("TOP needs a message number and a line count")
		return
	}
	n, err := strconv.Atoi(strings.TrimSpace(linesStr))
	if err != nil || n < 0 {
		s.err("invalid line count")
		return
	}
	_, m, ok2 := s.message(strings.TrimSpace(numStr))
	if !ok2 {
		return
	}
	data, err := m.Read()
	if err != nil {
		s.err("cannot read message")
		return
	}
	s.ok("top of message follows")
	// TOP must not change the Seen state: it is a preview.
	s.writeDotted(string(data), n)
}

func (s *session) cmdDele(arg string) {
	if !s.requireAuth() {
		return
	}
	n, _, ok := s.message(arg)
	if !ok {
		return
	}
	s.del[n] = true
	s.ok("message %d deleted", n)
}

func (s *session) cmdRset() {
	if !s.requireAuth() {
		return
	}
	s.del = map[int]bool{}
	s.ok("maildrop has %d messages (%d octets)", len(s.msgs), s.totalSize())
}

// cmdQuit enters the UPDATE state: deletions requested during the
// session are applied now, and only now.
func (s *session) cmdQuit() {
	if !s.authd || len(s.del) == 0 {
		s.ok("%s closing connection", s.set().Hostname)
		return
	}
	removed := 0
	for i, m := range s.msgs {
		if !s.del[i+1] {
			continue
		}
		if err := s.mbox.SetFlags(m, m.Flags.Add(maildir.FlagDeleted)); err != nil {
			s.srv.log.Error("delete failed", "protocol", "pop3",
				"user", s.user, "error", err.Error())
			continue
		}
		removed++
	}
	if _, err := s.mbox.Expunge(); err != nil {
		s.srv.log.Error("expunge failed", "protocol", "pop3",
			"user", s.user, "error", err.Error())
		s.err("some messages were not removed")
		return
	}
	s.srv.log.Info("messages deleted",
		"event", "pop3_delete", "protocol", "pop3", "user", s.user, "count", removed)
	s.ok("%s closing connection, %d messages deleted", s.set().Hostname, removed)
}
