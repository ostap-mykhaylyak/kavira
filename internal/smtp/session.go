package smtp

import (
	"bufio"
	"bytes"
	stdtls "crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strings"
	"time"

	"github.com/ostap-mykhaylyak/kavira/internal/auth"
	"github.com/ostap-mykhaylyak/kavira/internal/storage"
)

const (
	// cmdTimeout bounds the wait for the next command line.
	cmdTimeout = 5 * time.Minute
	// dataTimeout bounds the whole DATA transfer.
	dataTimeout = 10 * time.Minute
	// maxLine bounds a single command line.
	maxLine = 2048
)

// session is one SMTP connection.
type session struct {
	srv  *Server
	conn net.Conn
	r    *bufio.Reader
	w    *bufio.Writer
	ip   string

	helo    string
	tls     bool
	authed  string // authenticated user address, "" = none
	from    string
	fromSet bool
	rcpts   []rcpt
}

type rcpt struct {
	addr   string
	remote bool // submission relay: enqueue instead of deliver
	mb     storage.Mailbox
}

func newSession(srv *Server, conn net.Conn, ip string) *session {
	return &session{
		srv:  srv,
		conn: conn,
		r:    bufio.NewReaderSize(conn, 4096),
		w:    bufio.NewWriterSize(conn, 4096),
		ip:   ip,
		tls:  srv.set.Load().ImplicitTLS,
	}
}

func (s *session) set() *Settings { return s.srv.set.Load() }

func (s *session) reply(line string) error {
	s.w.WriteString(line)
	s.w.WriteString("\r\n")
	return s.w.Flush()
}

// readLine reads one CRLF-terminated command line, enforcing maxLine.
func (s *session) readLine() (string, error) {
	s.conn.SetReadDeadline(time.Now().Add(cmdTimeout))
	line, err := s.r.ReadSlice('\n')
	if err == bufio.ErrBufferFull || len(line) > maxLine {
		// Drain the rest of the oversized line.
		for err == bufio.ErrBufferFull {
			_, err = s.r.ReadSlice('\n')
		}
		s.reply("500 5.5.2 line too long")
		return "", nil // caller loops for the next command
	}
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(line), "\r\n"), nil
}

func (s *session) run() {
	defer s.conn.Close()

	set := s.set()
	if err := s.reply("220 " + set.Hostname + " ESMTP Kavira"); err != nil {
		return
	}

	for {
		line, err := s.readLine()
		if err != nil {
			return // timeout or client gone
		}
		if line == "" {
			continue
		}
		cmd, arg, _ := strings.Cut(line, " ")
		var quit bool
		switch strings.ToUpper(cmd) {
		case "HELO":
			quit = s.cmdHelo(arg, false)
		case "EHLO":
			quit = s.cmdHelo(arg, true)
		case "STARTTLS":
			quit = s.cmdStartTLS()
		case "MAIL":
			s.cmdMail(arg)
		case "RCPT":
			s.cmdRcpt(arg)
		case "DATA":
			quit = s.cmdData()
		case "RSET":
			s.resetTransaction()
			s.reply("250 2.0.0 OK")
		case "NOOP":
			s.reply("250 2.0.0 OK")
		case "QUIT":
			s.reply("221 2.0.0 " + s.set().Hostname + " closing connection")
			return
		case "VRFY", "EXPN":
			// Permanently disabled: user enumeration.
			s.reply("502 5.5.1 command disabled")
		case "AUTH":
			s.cmdAuth(arg)
		case "HELP":
			s.reply("214 2.0.0 see RFC 5321")
		default:
			s.reply("500 5.5.1 command not recognized")
		}
		if quit {
			return
		}
	}
}

func (s *session) resetTransaction() {
	s.from = ""
	s.fromSet = false
	s.rcpts = nil
}

func (s *session) cmdHelo(arg string, extended bool) (quit bool) {
	if arg == "" {
		s.reply("501 5.5.4 hostname required")
		return false
	}
	s.helo = sanitizeHelo(arg)
	s.resetTransaction()
	set := s.set()
	if !extended {
		s.reply("250 " + set.Hostname)
		return false
	}
	caps := []string{
		"250-" + set.Hostname,
		"250-PIPELINING",
		fmt.Sprintf("250-SIZE %d", set.MaxSize),
		"250-8BITMIME",
		"250-SMTPUTF8",
	}
	if set.TLS != nil && !s.tls {
		caps = append(caps, "250-STARTTLS")
	}
	// AUTH is offered only on submission and only over TLS: PLAIN and
	// LOGIN carry the password, they never travel in clear.
	if set.Mode == ModeSubmission && s.tls && s.srv.backend.Authenticate != nil {
		caps = append(caps, "250-AUTH PLAIN LOGIN")
	}
	caps[len(caps)-1] = "250 " + caps[len(caps)-1][4:]
	for _, c := range caps[:len(caps)-1] {
		s.w.WriteString(c + "\r\n")
	}
	s.reply(caps[len(caps)-1])
	return false
}

func (s *session) cmdStartTLS() (quit bool) {
	set := s.set()
	switch {
	case set.TLS == nil:
		s.reply("454 4.7.0 TLS not available")
		return false
	case s.tls:
		s.reply("503 5.5.1 already in TLS")
		return false
	}
	if err := s.reply("220 2.0.0 ready to start TLS"); err != nil {
		return true
	}
	tlsConn := stdtls.Server(s.conn, set.TLS)
	s.conn.SetReadDeadline(time.Now().Add(cmdTimeout))
	if err := tlsConn.Handshake(); err != nil {
		s.srv.log.Warn("starttls handshake failed",
			"event", "tls_error", "protocol", "smtp", "ip", s.ip, "error", err.Error())
		return true
	}
	s.conn = tlsConn
	s.r = bufio.NewReaderSize(tlsConn, 4096)
	s.w = bufio.NewWriterSize(tlsConn, 4096)
	s.tls = true
	// RFC 3207: the protocol state resets, the client must EHLO again.
	s.helo = ""
	s.resetTransaction()
	return false
}

// cmdAuth implements AUTH PLAIN and AUTH LOGIN, submission-only and
// TLS-only.
func (s *session) cmdAuth(arg string) {
	set := s.set()
	if set.Mode != ModeSubmission || s.srv.backend.Authenticate == nil {
		s.reply("503 5.5.1 authentication not available on this port")
		return
	}
	if !s.tls {
		s.reply("530 5.7.0 must issue STARTTLS first")
		return
	}
	if s.authed != "" {
		s.reply("503 5.5.1 already authenticated")
		return
	}

	mech, rest, _ := strings.Cut(arg, " ")
	var user, pass string
	var ok bool
	switch strings.ToUpper(mech) {
	case "PLAIN":
		user, pass, ok = s.authPlain(rest)
	case "LOGIN":
		user, pass, ok = s.authLogin()
	default:
		s.reply("504 5.5.4 mechanism not supported")
		return
	}
	if !ok {
		return // reply already sent
	}

	switch err := s.srv.backend.Authenticate(user, pass, s.ip); {
	case err == nil:
		s.authed = strings.ToLower(user)
		s.srv.log.Info("authentication succeeded",
			"event", "auth_ok", "protocol", "smtp", "ip", s.ip, "user", s.authed)
		s.reply("235 2.7.0 authentication successful")
	case errors.Is(err, auth.ErrLocked):
		s.srv.log.Warn("authentication locked out",
			"event", "auth_locked", "protocol", "smtp", "ip", s.ip, "user", user, "action", "reject")
		s.reply("454 4.7.0 too many failed attempts, try again later")
	default:
		s.srv.log.Warn("authentication failed",
			"event", "auth_failed", "protocol", "smtp", "ip", s.ip, "user", user, "action", "reject")
		s.reply("535 5.7.8 authentication credentials invalid")
	}
}

// authPlain handles AUTH PLAIN with or without an initial response.
func (s *session) authPlain(initial string) (user, pass string, ok bool) {
	resp := initial
	if resp == "" {
		if err := s.reply("334 "); err != nil {
			return "", "", false
		}
		line, err := s.readLine()
		if err != nil || line == "*" {
			s.reply("501 5.7.0 authentication cancelled")
			return "", "", false
		}
		resp = line
	}
	raw, err := base64.StdEncoding.DecodeString(resp)
	if err != nil {
		s.reply("501 5.5.2 invalid base64")
		return "", "", false
	}
	// authzid \0 authcid \0 password
	parts := strings.Split(string(raw), "\x00")
	if len(parts) != 3 || parts[1] == "" {
		s.reply("501 5.5.2 invalid PLAIN response")
		return "", "", false
	}
	return parts[1], parts[2], true
}

// authLogin handles the two-step AUTH LOGIN dialogue.
func (s *session) authLogin() (user, pass string, ok bool) {
	for i, prompt := range []string{"334 VXNlcm5hbWU6", "334 UGFzc3dvcmQ6"} {
		if err := s.reply(prompt); err != nil {
			return "", "", false
		}
		line, err := s.readLine()
		if err != nil || line == "*" {
			s.reply("501 5.7.0 authentication cancelled")
			return "", "", false
		}
		raw, derr := base64.StdEncoding.DecodeString(line)
		if derr != nil {
			s.reply("501 5.5.2 invalid base64")
			return "", "", false
		}
		if i == 0 {
			user = string(raw)
		} else {
			pass = string(raw)
		}
	}
	return user, pass, true
}

func (s *session) cmdMail(arg string) {
	if s.helo == "" {
		s.reply("503 5.5.1 send HELO/EHLO first")
		return
	}
	if s.fromSet {
		s.reply("503 5.5.1 nested MAIL command")
		return
	}
	set := s.set()
	if set.Mode == ModeSubmission && s.authed == "" {
		s.reply("530 5.7.0 authentication required")
		return
	}
	addr, params, err := parsePath(arg, "FROM:")
	if err != nil {
		s.reply("501 5.5.4 " + err.Error())
		return
	}
	size, err := sizeParam(params)
	if err != nil {
		s.reply("501 5.5.4 invalid SIZE parameter")
		return
	}
	if size > set.MaxSize {
		s.reply(fmt.Sprintf("552 5.3.4 message exceeds maximum size %d", set.MaxSize))
		return
	}
	addr = strings.ToLower(addr)
	// Submission: the sender identity is the authenticated user, not
	// whatever the client claims. Spoofed From at the envelope level
	// is refused and logged.
	if set.Mode == ModeSubmission && addr != s.authed {
		s.srv.log.Warn("sender spoof rejected",
			"event", "sender_mismatch", "protocol", "smtp", "ip", s.ip,
			"user", s.authed, "claimed", addr, "action", "reject")
		s.reply("553 5.7.1 sender address must be the authenticated user")
		return
	}
	// addr may be empty on port 25: the null reverse-path of bounces.
	s.from = addr
	s.fromSet = true
	s.reply("250 2.1.0 OK")
}

func (s *session) cmdRcpt(arg string) {
	if !s.fromSet {
		s.reply("503 5.5.1 need MAIL before RCPT")
		return
	}
	set := s.set()
	if len(s.rcpts) >= set.MaxRecipients {
		s.reply("452 4.5.3 too many recipients")
		return
	}
	addr, _, err := parsePath(arg, "TO:")
	if err != nil {
		s.reply("501 5.5.4 " + err.Error())
		return
	}
	addr = strings.ToLower(strings.TrimSpace(addr))
	// RFC 5321 requires accepting a bare <postmaster>.
	if addr == "postmaster" {
		if pm := s.srv.backend.Postmaster(); pm != "" {
			addr = pm
		}
	}
	_, domain, ok := splitAddr(addr)
	if !ok {
		s.reply("501 5.1.3 invalid address")
		return
	}

	local := s.srv.backend.IsLocalDomain(domain)
	if set.Mode == ModeInbound {
		// ANTI OPEN RELAY: port 25 only ever accepts mail FOR the
		// hosted domains. Everything else is refused,
		// unconditionally.
		if !local {
			s.srv.log.Warn("relay denied",
				"event", "relay_denied", "protocol", "smtp", "ip", s.ip,
				"from", s.from, "rcpt", addr, "action", "reject")
			s.reply("554 5.7.1 relay access denied")
			return
		}
		if !set.Limits.RcptAllowed(s.ip) {
			s.srv.log.Warn("recipient rate limited",
				"event", "ratelimit", "protocol", "smtp", "ip", s.ip, "action", "reject_rcpt")
			s.reply("452 4.4.5 too many recipients, slow down")
			return
		}
	} else {
		// Submission: per-user outbound protection (compromised
		// account containment).
		if !set.OutLimits.RcptAllowed(s.authed) {
			s.srv.log.Warn("outbound recipient limit exceeded",
				"event", "ratelimit_out", "protocol", "smtp", "ip", s.ip,
				"user", s.authed, "action", "reject_rcpt")
			s.reply("452 4.4.5 recipient quota exceeded, try again later")
			return
		}
	}

	if !local {
		// Remote recipient on submission: relay via the queue.
		s.rcpts = append(s.rcpts, rcpt{addr: addr, remote: true})
		s.reply("250 2.1.5 OK")
		return
	}
	mb, ok := s.srv.backend.Lookup(addr)
	if !ok {
		s.reply("550 5.1.1 no such user here")
		return
	}
	s.rcpts = append(s.rcpts, rcpt{addr: addr, mb: mb})
	s.reply("250 2.1.5 OK")
}

func (s *session) cmdData() (quit bool) {
	if len(s.rcpts) == 0 {
		s.reply("503 5.5.1 need RCPT before DATA")
		return false
	}
	set := s.set()
	if set.Mode == ModeInbound {
		if !set.Limits.MsgAllowed(s.ip) {
			s.srv.log.Warn("message rate limited",
				"event", "ratelimit", "protocol", "smtp", "ip", s.ip, "action", "reject_message")
			s.reply("421 4.7.0 too many messages, closing connection")
			return true
		}
	} else if !set.OutLimits.MsgAllowed(s.authed) {
		s.srv.log.Warn("outbound message limit exceeded",
			"event", "ratelimit_out", "protocol", "smtp", "ip", s.ip,
			"user", s.authed, "action", "suspend_sending")
		s.reply("452 4.2.1 sending quota exceeded, try again later")
		return false
	} else if s.srv.backend.MaySend != nil {
		// Reputation and warm-up: a burned sender or a brand-new
		// domain over its daily ramp is held back here.
		_, domain, _ := splitAddr(s.authed)
		if ok, reason := s.srv.backend.MaySend(s.authed, domain); !ok {
			s.srv.log.Warn("sending refused by reputation",
				"event", "reputation_block", "protocol", "smtp", "ip", s.ip,
				"user", s.authed, "reason", reason, "action", "reject")
			s.reply("450 4.7.1 " + reason)
			return false
		}
	}
	if err := s.reply("354 end data with <CRLF>.<CRLF>"); err != nil {
		return true
	}

	s.conn.SetReadDeadline(time.Now().Add(dataTimeout))
	dot := textproto.NewReader(s.r).DotReader()
	var buf bytes.Buffer
	n, err := io.Copy(&buf, io.LimitReader(dot, set.MaxSize+1))
	if err != nil {
		return true // client gone or timeout
	}
	if n > set.MaxSize {
		// Consume the rest of the message so the channel stays usable.
		if _, err := io.Copy(io.Discard, dot); err != nil {
			return true
		}
		s.resetTransaction()
		s.reply(fmt.Sprintf("552 5.3.4 message exceeds maximum size %d", set.MaxSize))
		return false
	}

	body := buf.Bytes()
	spam := false
	var authResults []byte

	// Inbound authentication pipeline: SPF/DKIM/DMARC on the raw
	// message, before any locally added header (DKIM verification
	// must see the message exactly as the signer's MTA sent it).
	if set.Mode == ModeInbound && s.srv.backend.Screen != nil {
		sr := s.srv.backend.Screen(s.ip, s.helo, s.from, body)
		switch sr.Action {
		case ScreenReject:
			s.srv.log.Warn("message rejected by policy",
				"event", "policy_reject", "protocol", "smtp", "ip", s.ip,
				"from", s.from, "reason", sr.Reason, "action", "reject")
			s.resetTransaction()
			s.reply("550 5.7.1 " + sr.Reason)
			return false
		case ScreenQuarantine:
			s.srv.log.Warn("message quarantined by policy",
				"event", "policy_quarantine", "protocol", "smtp", "ip", s.ip,
				"from", s.from, "reason", sr.Reason, "action", "quarantine")
			spam = true
		}
		authResults = append([]byte(sr.AuthResults), sr.SpamHeader...)
	}

	msg := s.assemble(body, authResults)

	// Submission: DKIM-sign with the sender domain's key, when one
	// exists. Signing failures are logged but do not block the mail.
	if set.Mode == ModeSubmission && s.srv.backend.Sign != nil {
		if _, domain, ok := splitAddr(s.from); ok {
			if signed, err := s.srv.backend.Sign(domain, msg); err == nil {
				msg = signed
			} else {
				s.srv.log.Error("dkim signing failed",
					"event", "dkim_error", "protocol", "smtp",
					"user", s.authed, "domain", domain, "error", err.Error())
			}
		}
	}

	accepted := 0
	for _, r := range s.rcpts {
		var err error
		if r.remote {
			err = s.srv.backend.Enqueue(s.from, r.addr, msg)
		} else {
			err = s.srv.backend.Deliver(r.mb, s.from, spam, msg)
		}
		if err != nil {
			s.srv.log.Error("delivery failed",
				"event", "delivery_error", "protocol", "smtp", "ip", s.ip,
				"rcpt", r.addr, "error", err.Error())
			continue
		}
		accepted++
	}
	if accepted == 0 {
		s.resetTransaction()
		s.reply("451 4.3.0 delivery failed, try again later")
		return false
	}
	event := "message_in"
	if set.Mode == ModeSubmission {
		event = "message_submitted"
		if s.srv.backend.Sent != nil {
			_, domain, _ := splitAddr(s.authed)
			s.srv.backend.Sent(s.authed, domain)
		}
	}
	s.srv.log.Info("message accepted",
		"event", event, "protocol", "smtp", "ip", s.ip, "user", s.authed,
		"from", s.from, "rcpts", len(s.rcpts), "size", n, "tls", s.tls)
	s.resetTransaction()
	s.reply("250 2.0.0 OK message accepted for delivery")
	return false
}

// assemble prepends the trace headers to the received body. Only the
// public hostname appears: never an internal IP or container name.
// Return-Path is NOT added here: it belongs to final delivery only,
// never to a message forwarded to another MTA.
func (s *session) assemble(body, extra []byte) []byte {
	set := s.set()
	with := "ESMTP"
	if s.tls {
		with = "ESMTPS"
	}
	if s.authed != "" {
		with = "ESMTPSA"
	}
	// The recorded source address is masked when it belongs to the
	// internal network of a containerized deployment: a message
	// relayed onward must not carry the host's private topology
	// (a webmail on the bridge submitting through kavira is the
	// common case). Public addresses pass through unchanged.
	source := set.Identity.MaskIP(s.ip)

	var b bytes.Buffer
	// Authentication-Results goes above our own Received, the
	// convention every major MTA follows: a reader walking down from
	// the top meets our verdict before the hop it describes.
	b.Write(extra) // already CRLF-terminated, empty when not screening
	fmt.Fprintf(&b, "Received: from %s (%s)\r\n\tby %s (Kavira) with %s",
		s.helo, source, set.Hostname, with)
	// The for clause names the recipient only when there is exactly
	// one: with several, disclosing the full list to each of them
	// would leak the envelope.
	if len(s.rcpts) == 1 {
		fmt.Fprintf(&b, "\r\n\tfor <%s>", s.rcpts[0].addr)
	}
	fmt.Fprintf(&b, ";\r\n\t%s\r\n", time.Now().Format(time.RFC1123Z))
	b.Write(body)
	return b.Bytes()
}

// splitAddr separates local part and lowercased domain.
func splitAddr(email string) (local, domain string, ok bool) {
	at := strings.LastIndex(email, "@")
	if at <= 0 || at == len(email)-1 {
		return "", "", false
	}
	return email[:at], strings.ToLower(email[at+1:]), true
}
