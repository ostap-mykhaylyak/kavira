package smtp

import (
	"bufio"
	"bytes"
	stdtls "crypto/tls"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strings"
	"time"

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
	from    string
	fromSet bool
	rcpts   []rcpt
}

type rcpt struct {
	addr string
	mb   storage.Mailbox
}

func newSession(srv *Server, conn net.Conn, ip string) *session {
	return &session{
		srv:  srv,
		conn: conn,
		r:    bufio.NewReaderSize(conn, 4096),
		w:    bufio.NewWriterSize(conn, 4096),
		ip:   ip,
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
			// Inbound port 25 never authenticates; submission (M2)
			// has its own listeners.
			s.reply("503 5.5.1 authentication not available on this port")
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

func (s *session) cmdMail(arg string) {
	if s.helo == "" {
		s.reply("503 5.5.1 send HELO/EHLO first")
		return
	}
	if s.fromSet {
		s.reply("503 5.5.1 nested MAIL command")
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
	set := s.set()
	if size > set.MaxSize {
		s.reply(fmt.Sprintf("552 5.3.4 message exceeds maximum size %d", set.MaxSize))
		return
	}
	// addr may be empty: the null reverse-path of bounces.
	s.from = strings.ToLower(addr)
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

	// ANTI OPEN RELAY: this listener only ever accepts mail FOR the
	// hosted domains. Everything else is refused, unconditionally.
	if !s.srv.backend.IsLocalDomain(domain) {
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
	if !set.Limits.MsgAllowed(s.ip) {
		s.srv.log.Warn("message rate limited",
			"event", "ratelimit", "protocol", "smtp", "ip", s.ip, "action", "reject_message")
		s.reply("421 4.7.0 too many messages, closing connection")
		return true
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

	msg := s.assemble(buf.Bytes())
	delivered := 0
	for _, r := range s.rcpts {
		if err := s.srv.backend.Deliver(r.mb, msg); err != nil {
			s.srv.log.Error("delivery failed",
				"event", "delivery_error", "protocol", "smtp", "ip", s.ip,
				"rcpt", r.addr, "error", err.Error())
			continue
		}
		delivered++
	}
	if delivered == 0 {
		s.resetTransaction()
		s.reply("451 4.3.0 local delivery failed, try again later")
		return false
	}
	s.srv.log.Info("message received",
		"event", "message_in", "protocol", "smtp", "ip", s.ip,
		"from", s.from, "rcpts", len(s.rcpts), "size", n, "tls", s.tls)
	s.resetTransaction()
	s.reply("250 2.0.0 OK message accepted for delivery")
	return false
}

// assemble prepends the trace headers to the received body. Only the
// public hostname appears: never an internal IP or container name.
func (s *session) assemble(body []byte) []byte {
	set := s.set()
	with := "ESMTP"
	if s.tls {
		with = "ESMTPS"
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "Return-Path: <%s>\r\n", s.from)
	fmt.Fprintf(&b, "Received: from %s (%s)\r\n\tby %s (Kavira) with %s\r\n",
		s.helo, s.ip, set.Hostname, with)
	if len(s.rcpts) == 1 {
		fmt.Fprintf(&b, "\tfor <%s>", s.rcpts[0].addr)
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
