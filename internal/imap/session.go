package imap

import (
	"bufio"
	stdtls "crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/ostap-mykhaylyak/kavira/internal/maildir"
)

// Session timeouts. RFC 3501 requires at least 30 minutes of
// inactivity before an autologout; IDLE gets its own longer bound.
const (
	idleTimeout     = 30 * time.Minute
	idleMaxDuration = 29 * time.Minute
	idlePollEvery   = 5 * time.Second
	maxLine         = 8192
)

// state is the IMAP connection state machine.
type state int

const (
	stateNotAuthenticated state = iota
	stateAuthenticated
	stateSelected
)

type session struct {
	srv  *Server
	conn net.Conn
	r    *bufio.Reader
	w    *bufio.Writer
	ip   string

	state    state
	tls      bool
	user     string
	root     string // account maildir
	mbox     *maildir.Mailbox
	readOnly bool

	// subscriptions are per-session only: kavira does not persist a
	// subscription list, so LSUB reports every existing mailbox.
	_ struct{}
}

func newSession(srv *Server, conn net.Conn) *session {
	return &session{
		srv:  srv,
		conn: conn,
		r:    bufio.NewReaderSize(conn, 4096),
		w:    bufio.NewWriterSize(conn, 16*1024),
		ip:   remoteIP(conn),
		tls:  srv.set.Load().ImplicitTLS,
	}
}

func (s *session) set() *Settings { return s.srv.set.Load() }

// out writes one CRLF-terminated line.
func (s *session) out(format string, args ...any) error {
	fmt.Fprintf(s.w, format, args...)
	s.w.WriteString("\r\n")
	return s.w.Flush()
}

// raw writes pre-formatted bytes (FETCH payloads carry literals).
func (s *session) raw(str string) {
	s.w.WriteString(str)
}

func (s *session) flush() error { return s.w.Flush() }

// readLine reads one command line, enforcing maxLine.
func (s *session) readLine() (string, error) {
	s.conn.SetReadDeadline(time.Now().Add(idleTimeout))
	line, err := s.r.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(line) > maxLine {
		return "", fmt.Errorf("line too long")
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// readLiteral sends the continuation request and reads n bytes.
func (s *session) readLiteral(n int) (string, error) {
	if int64(n) > s.set().MaxSize {
		return "", fmt.Errorf("literal too large")
	}
	if err := s.out("+ ready for literal"); err != nil {
		return "", err
	}
	buf := make([]byte, n)
	s.conn.SetReadDeadline(time.Now().Add(idleTimeout))
	if _, err := io.ReadFull(s.r, buf); err != nil {
		return "", err
	}
	// The rest of the command follows on the same logical line.
	return string(buf), nil
}

// capabilities lists what the server offers in the current state.
func (s *session) capabilities() string {
	caps := []string{"IMAP4rev1", "IDLE", "UIDPLUS", "MOVE", "NAMESPACE", "CHILDREN"}
	set := s.set()
	if !s.tls && set.TLS != nil {
		caps = append(caps, "STARTTLS")
	}
	if !s.tls {
		// No credentials may cross a plaintext channel.
		caps = append(caps, "LOGINDISABLED")
	} else if s.state == stateNotAuthenticated {
		caps = append(caps, "AUTH=PLAIN", "AUTH=LOGIN")
	}
	return strings.Join(caps, " ")
}

func (s *session) run() {
	defer s.conn.Close()

	if err := s.out("* OK [CAPABILITY %s] %s Kavira IMAP4rev1 ready",
		s.capabilities(), s.set().Hostname); err != nil {
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
		if quit := s.dispatch(line); quit {
			return
		}
	}
}

// dispatch parses and runs one command line.
func (s *session) dispatch(line string) (quit bool) {
	p := &parser{line: line, readLiteral: s.readLiteral}
	tagTok, err := p.next()
	if err != nil {
		s.out("* BAD invalid command line")
		return false
	}
	tag := tagTok.str
	cmdTok, err := p.next()
	if err != nil {
		s.out("%s BAD missing command", tag)
		return false
	}
	cmd := cmdTok.upper()

	// UID prefixes FETCH/STORE/SEARCH/COPY/MOVE and switches them to
	// operating on UIDs instead of sequence numbers.
	uidMode := false
	if cmd == "UID" {
		sub, err := p.next()
		if err != nil {
			s.out("%s BAD UID needs a command", tag)
			return false
		}
		uidMode = true
		cmd = sub.upper()
		switch cmd {
		case "FETCH", "STORE", "SEARCH", "COPY", "MOVE", "EXPUNGE":
		default:
			s.out("%s BAD UID does not apply to %s", tag, cmd)
			return false
		}
	}

	switch cmd {
	case "CAPABILITY":
		s.out("* CAPABILITY %s", s.capabilities())
		s.out("%s OK CAPABILITY completed", tag)
	case "NOOP":
		s.cmdNoop(tag)
	case "LOGOUT":
		s.out("* BYE logging out")
		s.out("%s OK LOGOUT completed", tag)
		return true
	case "STARTTLS":
		return s.cmdStartTLS(tag)
	case "LOGIN":
		s.cmdLogin(tag, p)
	case "AUTHENTICATE":
		s.cmdAuthenticate(tag, p)
	case "SELECT", "EXAMINE":
		s.cmdSelect(tag, p, cmd == "EXAMINE")
	case "LIST", "LSUB":
		s.cmdList(tag, p)
	case "STATUS":
		s.cmdStatus(tag, p)
	case "CREATE":
		s.cmdCreate(tag, p)
	case "DELETE":
		s.cmdDelete(tag, p)
	case "SUBSCRIBE", "UNSUBSCRIBE":
		// Every mailbox is implicitly subscribed: kavira keeps no
		// subscription list, so these succeed if the mailbox exists.
		s.cmdSubscribe(tag, p)
	case "NAMESPACE":
		s.out(`* NAMESPACE (("" ".")) NIL NIL`)
		s.out("%s OK NAMESPACE completed", tag)
	case "CHECK":
		s.requireSelected(tag, func() { s.out("%s OK CHECK completed", tag) })
	case "CLOSE":
		s.cmdClose(tag)
	case "UNSELECT":
		s.requireSelected(tag, func() {
			s.mbox, s.state = nil, stateAuthenticated
			s.out("%s OK UNSELECT completed", tag)
		})
	case "EXPUNGE":
		s.cmdExpunge(tag)
	case "APPEND":
		s.cmdAppend(tag, p)
	case "FETCH":
		s.cmdFetch(tag, p, uidMode)
	case "STORE":
		s.cmdStore(tag, p, uidMode)
	case "SEARCH":
		s.cmdSearch(tag, p, uidMode)
	case "COPY":
		s.cmdCopyMove(tag, p, uidMode, false)
	case "MOVE":
		s.cmdCopyMove(tag, p, uidMode, true)
	case "IDLE":
		s.cmdIdle(tag)
	default:
		s.out("%s BAD unknown command %s", tag, cmd)
	}
	return false
}

// requireAuth runs fn only when the session is authenticated.
func (s *session) requireAuth(tag string, fn func()) {
	if s.state == stateNotAuthenticated {
		s.out("%s NO not authenticated", tag)
		return
	}
	fn()
}

// requireSelected runs fn only when a mailbox is selected.
func (s *session) requireSelected(tag string, fn func()) {
	if s.state != stateSelected {
		s.out("%s NO no mailbox selected", tag)
		return
	}
	fn()
}

func (s *session) cmdNoop(tag string) {
	// NOOP is the polling client's way to learn about new mail.
	if s.state == stateSelected {
		s.pollAndReport()
	}
	s.out("%s OK NOOP completed", tag)
}

func (s *session) cmdStartTLS(tag string) (quit bool) {
	set := s.set()
	if set.TLS == nil {
		s.out("%s NO TLS not available", tag)
		return false
	}
	if s.tls {
		s.out("%s BAD already in TLS", tag)
		return false
	}
	if err := s.out("%s OK begin TLS negotiation", tag); err != nil {
		return true
	}
	tlsConn := stdtls.Server(s.conn, set.TLS)
	s.conn.SetReadDeadline(time.Now().Add(time.Minute))
	if err := tlsConn.Handshake(); err != nil {
		s.srv.log.Warn("starttls handshake failed",
			"event", "tls_error", "protocol", "imap", "ip", s.ip, "error", err.Error())
		return true
	}
	s.conn = tlsConn
	s.r = bufio.NewReaderSize(tlsConn, 4096)
	s.w = bufio.NewWriterSize(tlsConn, 16*1024)
	s.tls = true
	return false
}

// authenticate performs the credential check shared by LOGIN and
// AUTHENTICATE.
func (s *session) authenticate(tag, user, pass string) {
	root, err := s.srv.backend.Authenticate(user, pass, s.ip)
	if err != nil {
		s.srv.log.Warn("authentication failed",
			"event", "auth_failed", "protocol", "imap", "ip", s.ip,
			"user", user, "action", "reject")
		s.out("%s NO [AUTHENTICATIONFAILED] authentication failed", tag)
		return
	}
	s.user, s.root, s.state = strings.ToLower(user), root, stateAuthenticated
	s.srv.log.Info("authentication succeeded",
		"event", "auth_ok", "protocol", "imap", "ip", s.ip, "user", s.user)
	s.out("%s OK [CAPABILITY %s] LOGIN completed", tag, s.capabilities())
}

func (s *session) cmdLogin(tag string, p *parser) {
	if !s.tls {
		s.out("%s NO [PRIVACYREQUIRED] STARTTLS required before LOGIN", tag)
		return
	}
	if s.state != stateNotAuthenticated {
		s.out("%s BAD already authenticated", tag)
		return
	}
	user, err1 := p.next()
	pass, err2 := p.next()
	if err1 != nil || err2 != nil {
		s.out("%s BAD LOGIN needs a username and a password", tag)
		return
	}
	s.authenticate(tag, user.str, pass.str)
}

func (s *session) cmdAuthenticate(tag string, p *parser) {
	if !s.tls {
		s.out("%s NO [PRIVACYREQUIRED] STARTTLS required before AUTHENTICATE", tag)
		return
	}
	if s.state != stateNotAuthenticated {
		s.out("%s BAD already authenticated", tag)
		return
	}
	mechTok, err := p.next()
	if err != nil {
		s.out("%s BAD AUTHENTICATE needs a mechanism", tag)
		return
	}

	readResp := func(prompt string) (string, bool) {
		if err := s.out("+ %s", prompt); err != nil {
			return "", false
		}
		line, err := s.readLine()
		if err != nil || line == "*" {
			s.out("%s BAD authentication cancelled", tag)
			return "", false
		}
		raw, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
		if derr != nil {
			s.out("%s BAD invalid base64", tag)
			return "", false
		}
		return string(raw), true
	}

	switch mechTok.upper() {
	case "PLAIN":
		// An initial response may be supplied inline.
		resp := ""
		if ir, err := p.next(); err == nil && ir.str != "=" {
			raw, derr := base64.StdEncoding.DecodeString(ir.str)
			if derr != nil {
				s.out("%s BAD invalid base64", tag)
				return
			}
			resp = string(raw)
		} else {
			var ok bool
			if resp, ok = readResp(""); !ok {
				return
			}
		}
		parts := strings.Split(resp, "\x00")
		if len(parts) != 3 || parts[1] == "" {
			s.out("%s BAD invalid PLAIN response", tag)
			return
		}
		s.authenticate(tag, parts[1], parts[2])
	case "LOGIN":
		user, ok := readResp("VXNlcm5hbWU6")
		if !ok {
			return
		}
		pass, ok := readResp("UGFzc3dvcmQ6")
		if !ok {
			return
		}
		s.authenticate(tag, user, pass)
	default:
		s.out("%s NO unsupported authentication mechanism", tag)
	}
}

// openMailbox loads a folder of the authenticated account.
func (s *session) openMailbox(name string) (*maildir.Mailbox, error) {
	return maildir.OpenMailbox(s.root, normalizeMailbox(name))
}

// normalizeMailbox maps the client's mailbox name onto a folder name.
// INBOX is case-insensitive per RFC 3501; hierarchy uses '.'.
func normalizeMailbox(name string) string {
	name = strings.TrimSpace(name)
	if strings.EqualFold(name, maildir.Inbox) {
		return maildir.Inbox
	}
	return strings.Trim(name, ".")
}

func (s *session) cmdSelect(tag string, p *parser, examine bool) {
	s.requireAuth(tag, func() {
		nameTok, err := p.next()
		if err != nil {
			s.out("%s BAD %s needs a mailbox name", tag, map[bool]string{true: "EXAMINE", false: "SELECT"}[examine])
			return
		}
		mb, err := s.openMailbox(nameTok.str)
		if err != nil {
			s.out("%s NO mailbox does not exist", tag)
			return
		}
		s.mbox, s.readOnly, s.state = mb, examine, stateSelected

		s.out("* %d EXISTS", mb.Count())
		s.out("* %d RECENT", mb.Recent())
		if u := mb.FirstUnseen(); u > 0 {
			s.out("* OK [UNSEEN %d] first unseen message", u)
		}
		s.out(`* FLAGS (\Answered \Flagged \Deleted \Seen \Draft)`)
		if examine {
			s.out(`* OK [PERMANENTFLAGS ()] read-only mailbox`)
		} else {
			s.out(`* OK [PERMANENTFLAGS (\Answered \Flagged \Deleted \Seen \Draft)] limited`)
		}
		s.out("* OK [UIDVALIDITY %d] UIDs valid", mb.UIDValidity())
		s.out("* OK [UIDNEXT %d] predicted next UID", mb.UIDNext())
		access := "READ-WRITE"
		if examine {
			access = "READ-ONLY"
		}
		s.out("%s OK [%s] %s completed", tag, access,
			map[bool]string{true: "EXAMINE", false: "SELECT"}[examine])
	})
}

func (s *session) cmdList(tag string, p *parser) {
	s.requireAuth(tag, func() {
		refTok, err1 := p.next()
		patTok, err2 := p.next()
		if err1 != nil || err2 != nil {
			s.out("%s BAD LIST needs a reference and a pattern", tag)
			return
		}
		// A bare "" pattern is the hierarchy delimiter probe.
		if patTok.str == "" {
			s.out(`* LIST (\Noselect) "." ""`)
			s.out("%s OK LIST completed", tag)
			return
		}
		folders, err := maildir.Folders(s.root)
		if err != nil {
			s.out("%s NO cannot list mailboxes", tag)
			return
		}
		pattern := refTok.str + patTok.str
		for _, f := range folders {
			if matchPattern(pattern, f) {
				s.out(`* LIST () "." %s`, quote(f))
			}
		}
		s.out("%s OK LIST completed", tag)
	})
}

// matchPattern implements the IMAP wildcards: '*' spans the hierarchy
// delimiter, '%' stops at it.
func matchPattern(pattern, name string) bool {
	if pattern == "" {
		return name == ""
	}
	// INBOX matches case-insensitively.
	if strings.EqualFold(pattern, name) {
		return true
	}
	return wildcard(pattern, name)
}

func wildcard(pat, s string) bool {
	for i := 0; i < len(pat); i++ {
		switch pat[i] {
		case '*':
			if i == len(pat)-1 {
				return true
			}
			for j := 0; j <= len(s); j++ {
				if wildcard(pat[i+1:], s[j:]) {
					return true
				}
			}
			return false
		case '%':
			// Matches anything but the delimiter.
			for j := 0; j <= len(s); j++ {
				if strings.Contains(s[:j], ".") {
					break
				}
				if wildcard(pat[i+1:], s[j:]) {
					return true
				}
			}
			return false
		default:
			if len(s) == 0 || s[0] != pat[i] {
				return false
			}
			s = s[1:]
		}
	}
	return len(s) == 0
}

func (s *session) cmdStatus(tag string, p *parser) {
	s.requireAuth(tag, func() {
		nameTok, err := p.next()
		if err != nil {
			s.out("%s BAD STATUS needs a mailbox", tag)
			return
		}
		itemsTok, err := p.next()
		if err != nil || !itemsTok.isList {
			s.out("%s BAD STATUS needs an item list", tag)
			return
		}
		mb, err := s.openMailbox(nameTok.str)
		if err != nil {
			s.out("%s NO mailbox does not exist", tag)
			return
		}
		var parts []string
		for _, it := range itemsTok.list {
			switch it.upper() {
			case "MESSAGES":
				parts = append(parts, fmt.Sprintf("MESSAGES %d", mb.Count()))
			case "RECENT":
				parts = append(parts, fmt.Sprintf("RECENT %d", mb.Recent()))
			case "UIDNEXT":
				parts = append(parts, fmt.Sprintf("UIDNEXT %d", mb.UIDNext()))
			case "UIDVALIDITY":
				parts = append(parts, fmt.Sprintf("UIDVALIDITY %d", mb.UIDValidity()))
			case "UNSEEN":
				parts = append(parts, fmt.Sprintf("UNSEEN %d", mb.Unseen()))
			}
		}
		s.out("* STATUS %s (%s)", quote(normalizeMailbox(nameTok.str)), strings.Join(parts, " "))
		s.out("%s OK STATUS completed", tag)
	})
}

func (s *session) cmdCreate(tag string, p *parser) {
	s.requireAuth(tag, func() {
		nameTok, err := p.next()
		if err != nil {
			s.out("%s BAD CREATE needs a mailbox name", tag)
			return
		}
		if err := maildir.CreateFolder(s.root, normalizeMailbox(nameTok.str)); err != nil {
			s.out("%s NO %v", tag, err)
			return
		}
		s.out("%s OK CREATE completed", tag)
	})
}

func (s *session) cmdDelete(tag string, p *parser) {
	s.requireAuth(tag, func() {
		nameTok, err := p.next()
		if err != nil {
			s.out("%s BAD DELETE needs a mailbox name", tag)
			return
		}
		if err := maildir.DeleteFolder(s.root, normalizeMailbox(nameTok.str)); err != nil {
			s.out("%s NO %v", tag, err)
			return
		}
		s.out("%s OK DELETE completed", tag)
	})
}

func (s *session) cmdSubscribe(tag string, p *parser) {
	s.requireAuth(tag, func() {
		nameTok, err := p.next()
		if err != nil {
			s.out("%s BAD needs a mailbox name", tag)
			return
		}
		if _, err := s.openMailbox(nameTok.str); err != nil {
			s.out("%s NO mailbox does not exist", tag)
			return
		}
		s.out("%s OK completed", tag)
	})
}

func (s *session) cmdClose(tag string) {
	s.requireSelected(tag, func() {
		if !s.readOnly {
			// CLOSE expunges silently, without EXPUNGE responses.
			if _, err := s.mbox.Expunge(); err != nil {
				s.srv.log.Error("expunge failed", "protocol", "imap",
					"user", s.user, "error", err.Error())
			}
		}
		s.mbox, s.state = nil, stateAuthenticated
		s.out("%s OK CLOSE completed", tag)
	})
}

func (s *session) cmdExpunge(tag string) {
	s.requireSelected(tag, func() {
		if s.readOnly {
			s.out("%s NO mailbox is read-only", tag)
			return
		}
		seqs, err := s.mbox.Expunge()
		if err != nil {
			s.out("%s NO expunge failed", tag)
			return
		}
		for _, seq := range seqs {
			s.out("* %d EXPUNGE", seq)
		}
		s.out("%s OK EXPUNGE completed", tag)
	})
}

func (s *session) cmdAppend(tag string, p *parser) {
	s.requireAuth(tag, func() {
		nameTok, err := p.next()
		if err != nil {
			s.out("%s BAD APPEND needs a mailbox", tag)
			return
		}
		var flags maildir.Flags
		var internal time.Time
		var data string
		// Remaining args: [(flags)] [internaldate] literal
		for {
			t, err := p.next()
			if err != nil {
				break
			}
			switch {
			case t.isList:
				for _, f := range t.list {
					if mf, ok := maildir.FlagFromIMAP(f.str); ok {
						flags = flags.Add(mf)
					}
				}
			case looksLikeDate(t.str):
				if d, err := time.Parse("02-Jan-2006 15:04:05 -0700", t.str); err == nil {
					internal = d
				}
			default:
				data = t.str
			}
		}
		if data == "" {
			s.out("%s BAD APPEND needs message data", tag)
			return
		}
		mb, err := s.openMailbox(nameTok.str)
		if err != nil {
			s.out("%s NO [TRYCREATE] mailbox does not exist", tag)
			return
		}
		m, err := mb.Append([]byte(data), flags, internal)
		if err != nil {
			s.srv.log.Error("append failed", "protocol", "imap",
				"user", s.user, "error", err.Error())
			s.out("%s NO append failed", tag)
			return
		}
		// If the appended-to mailbox is the selected one, the client
		// must learn the new count.
		if s.state == stateSelected && s.mbox.Folder() == mb.Folder() {
			s.mbox.Refresh()
			s.out("* %d EXISTS", s.mbox.Count())
		}
		s.out("%s OK [APPENDUID %d %d] APPEND completed", tag, mb.UIDValidity(), m.UID)
	})
}

// looksLikeDate reports whether a token is an IMAP INTERNALDATE.
func looksLikeDate(s string) bool {
	return len(s) >= 20 && strings.Count(s, "-") >= 2 && strings.Contains(s, ":")
}

// pollAndReport refreshes the selected mailbox and emits untagged
// EXISTS/RECENT when something changed.
func (s *session) pollAndReport() bool {
	if s.mbox == nil {
		return false
	}
	before := s.mbox.Count()
	if err := s.mbox.Refresh(); err != nil {
		return false
	}
	if s.mbox.Count() != before {
		s.out("* %d EXISTS", s.mbox.Count())
		s.out("* %d RECENT", s.mbox.Recent())
		return true
	}
	return false
}

// cmdIdle implements RFC 2177: the client parks, the server pushes
// mailbox changes until DONE arrives or the idle window expires.
func (s *session) cmdIdle(tag string) {
	s.requireSelected(tag, func() {
		if err := s.out("+ idling"); err != nil {
			return
		}
		done := make(chan error, 1)
		go func() {
			// A single blocking read: the only thing a client may send
			// while idling is DONE.
			s.conn.SetReadDeadline(time.Now().Add(idleMaxDuration + time.Minute))
			line, err := s.r.ReadString('\n')
			if err != nil {
				done <- err
				return
			}
			if strings.EqualFold(strings.TrimSpace(line), "DONE") {
				done <- nil
				return
			}
			done <- fmt.Errorf("unexpected input while idling")
		}()

		tick := time.NewTicker(idlePollEvery)
		defer tick.Stop()
		deadline := time.After(idleMaxDuration)
		for {
			select {
			case err := <-done:
				if err != nil {
					return // client gone or protocol violation
				}
				s.out("%s OK IDLE terminated", tag)
				return
			case <-tick.C:
				s.pollAndReport()
			case <-deadline:
				// Politely end a long IDLE so the connection does not
				// rot behind a NAT idle timeout.
				s.out("* BYE idle timeout")
				s.out("%s OK IDLE terminated", tag)
				return
			}
		}
	})
}
