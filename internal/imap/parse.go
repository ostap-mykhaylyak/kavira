// Package imap implements an IMAP4rev1 server (RFC 3501) over the
// Maildir storage, including IDLE (RFC 2177) and MOVE (RFC 6851).
//
// Mail access is per-user: a session sees exactly the mailboxes of
// the account it authenticated as. AUTHENTICATE and LOGIN are refused
// on a plaintext channel — LOGINDISABLED is advertised until the
// connection is encrypted, so no client ever sends a password in the
// clear.
package imap

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// token is one parsed IMAP argument.
type token struct {
	// str is the value of an atom, quoted string or literal.
	str string
	// list holds the elements of a parenthesized list.
	list []token
	// isList distinguishes an empty list from an empty string.
	isList bool
}

// String renders a token for error messages and simple comparisons.
func (t token) String() string { return t.str }

// upper returns the token value uppercased (IMAP keywords are
// case-insensitive).
func (t token) upper() string { return strings.ToUpper(t.str) }

// parser tokenizes an IMAP command line. Literals ({n}) are resolved
// through readLiteral, which the session supplies: reading a literal
// requires sending a continuation response first.
type parser struct {
	line string
	pos  int
	// readLiteral fetches n bytes from the connection after sending
	// the "+ ready" continuation.
	readLiteral func(n int) (string, error)
}

var errParse = errors.New("parse error")

func (p *parser) eof() bool { return p.pos >= len(p.line) }

func (p *parser) skipSpace() {
	for p.pos < len(p.line) && p.line[p.pos] == ' ' {
		p.pos++
	}
}

// peek returns the next byte without consuming it.
func (p *parser) peek() byte {
	if p.eof() {
		return 0
	}
	return p.line[p.pos]
}

// next reads one token: atom, quoted string, literal or list.
func (p *parser) next() (token, error) {
	p.skipSpace()
	if p.eof() {
		return token{}, errParse
	}
	switch c := p.peek(); c {
	case '(':
		return p.parseList()
	case '"':
		return p.parseQuoted()
	case '{':
		return p.parseLiteral()
	default:
		return p.parseAtom()
	}
}

// rest returns the remainder of the line verbatim (used for command
// arguments parsed by a dedicated grammar, like FETCH items).
func (p *parser) rest() string {
	p.skipSpace()
	s := p.line[p.pos:]
	p.pos = len(p.line)
	return s
}

func (p *parser) parseAtom() (token, error) {
	start := p.pos
	for p.pos < len(p.line) {
		c := p.line[p.pos]
		if c == ' ' || c == '(' || c == ')' {
			break
		}
		p.pos++
	}
	if p.pos == start {
		return token{}, errParse
	}
	return token{str: p.line[start:p.pos]}, nil
}

func (p *parser) parseQuoted() (token, error) {
	p.pos++ // opening quote
	var b strings.Builder
	for p.pos < len(p.line) {
		c := p.line[p.pos]
		switch c {
		case '\\':
			// Only \" and \\ are defined escapes.
			if p.pos+1 >= len(p.line) {
				return token{}, errParse
			}
			p.pos++
			b.WriteByte(p.line[p.pos])
			p.pos++
		case '"':
			p.pos++
			return token{str: b.String()}, nil
		default:
			b.WriteByte(c)
			p.pos++
		}
	}
	return token{}, errParse // unterminated
}

func (p *parser) parseLiteral() (token, error) {
	end := strings.IndexByte(p.line[p.pos:], '}')
	if end < 0 || p.readLiteral == nil {
		return token{}, errParse
	}
	spec := p.line[p.pos+1 : p.pos+end]
	// LITERAL+ (RFC 7888) marks a non-synchronizing literal with '+';
	// we do not advertise it, but tolerate the suffix.
	spec = strings.TrimSuffix(spec, "+")
	n, err := strconv.Atoi(spec)
	if err != nil || n < 0 || n > 64*1024*1024 {
		return token{}, errParse
	}
	// A literal is always the last thing on the line.
	p.pos = len(p.line)
	s, err := p.readLiteral(n)
	if err != nil {
		return token{}, err
	}
	return token{str: s}, nil
}

func (p *parser) parseList() (token, error) {
	p.pos++ // '('
	out := token{isList: true}
	for {
		p.skipSpace()
		if p.eof() {
			return token{}, errParse
		}
		if p.peek() == ')' {
			p.pos++
			return out, nil
		}
		t, err := p.next()
		if err != nil {
			return token{}, err
		}
		out.list = append(out.list, t)
	}
}

// all consumes the remaining tokens of the line.
func (p *parser) all() ([]token, error) {
	var out []token
	for {
		p.skipSpace()
		if p.eof() {
			return out, nil
		}
		t, err := p.next()
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
}

// seqSet is a parsed IMAP sequence set ("1", "2:5", "1,3:*").
type seqSet struct {
	ranges [][2]uint32
}

// parseSeqSet parses a sequence set. "*" becomes maxUint32, resolved
// by the caller against the mailbox size.
func parseSeqSet(s string) (*seqSet, error) {
	if s == "" {
		return nil, errParse
	}
	set := &seqSet{}
	for _, part := range strings.Split(s, ",") {
		lo, hi, found := strings.Cut(part, ":")
		a, err := parseSeqNum(lo)
		if err != nil {
			return nil, err
		}
		b := a
		if found {
			if b, err = parseSeqNum(hi); err != nil {
				return nil, err
			}
		}
		if a > b {
			a, b = b, a
		}
		set.ranges = append(set.ranges, [2]uint32{a, b})
	}
	return set, nil
}

func parseSeqNum(s string) (uint32, error) {
	if s == "*" {
		return ^uint32(0), nil
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil || n == 0 {
		return 0, errParse
	}
	return uint32(n), nil
}

// contains reports whether n is in the set. max is the value "*"
// stands for (the highest message number or UID in the mailbox).
func (s *seqSet) contains(n, max uint32) bool {
	for _, r := range s.ranges {
		lo, hi := r[0], r[1]
		if lo == ^uint32(0) {
			lo = max
		}
		if hi == ^uint32(0) {
			hi = max
		}
		if lo > hi {
			lo, hi = hi, lo
		}
		if n >= lo && n <= hi {
			return true
		}
	}
	return false
}

// quote renders a string as an IMAP quoted string.
func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, c := range []byte(s) {
		if c == '"' || c == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	b.WriteByte('"')
	return b.String()
}

// literal renders a string as an IMAP literal, which is how arbitrary
// binary message data must be sent.
func literal(s string) string {
	return fmt.Sprintf("{%d}\r\n%s", len(s), s)
}
