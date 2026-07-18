package imap

import (
	"bytes"
	"fmt"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/ostap-mykhaylyak/kavira/internal/maildir"
)

// selected resolves a sequence set against the selected mailbox,
// interpreting the numbers as UIDs when uidMode is set.
func (s *session) selected(set *seqSet, uidMode bool) []*maildir.Message {
	msgs := s.mbox.Messages()
	var out []*maildir.Message
	if uidMode {
		var max uint32
		if n := len(msgs); n > 0 {
			max = msgs[n-1].UID
		}
		for _, m := range msgs {
			if set.contains(m.UID, max) {
				out = append(out, m)
			}
		}
		return out
	}
	max := uint32(len(msgs))
	for _, m := range msgs {
		if set.contains(m.Seq, max) {
			out = append(out, m)
		}
	}
	return out
}

func (s *session) cmdFetch(tag string, p *parser, uidMode bool) {
	s.requireSelected(tag, func() {
		setTok, err := p.next()
		if err != nil {
			s.out("%s BAD FETCH needs a sequence set", tag)
			return
		}
		set, err := parseSeqSet(setTok.str)
		if err != nil {
			s.out("%s BAD invalid sequence set", tag)
			return
		}
		items := strings.TrimSpace(p.rest())
		if items == "" {
			s.out("%s BAD FETCH needs data items", tag)
			return
		}

		for _, m := range s.selected(set, uidMode) {
			payload, markSeen := s.fetchItems(m, items, uidMode)
			if markSeen && !s.readOnly && !m.Flags.Has(maildir.FlagSeen) {
				// A non-peeking BODY[] fetch implicitly sets \Seen.
				if err := s.mbox.SetFlags(m, m.Flags.Add(maildir.FlagSeen)); err == nil {
					payload = append(payload, "FLAGS ("+strings.Join(m.Flags.IMAPFlags(m.Recent), " ")+")")
				}
			}
			s.raw(fmt.Sprintf("* %d FETCH (%s)\r\n", m.Seq, strings.Join(payload, " ")))
		}
		s.flush()
		s.out("%s OK FETCH completed", tag)
	})
}

// fetchItems renders the requested data items for one message. It
// reports whether the fetch implicitly marks the message \Seen.
func (s *session) fetchItems(m *maildir.Message, spec string, uidMode bool) (out []string, markSeen bool) {
	// A UID FETCH always reports the UID, whether asked for or not.
	needUID := uidMode

	for _, item := range splitItems(spec) {
		up := strings.ToUpper(item)
		switch {
		case up == "ALL", up == "FAST", up == "FULL":
			out = append(out,
				"FLAGS ("+strings.Join(m.Flags.IMAPFlags(m.Recent), " ")+")",
				"INTERNALDATE "+quote(m.Internal.Format("02-Jan-2006 15:04:05 -0700")),
				fmt.Sprintf("RFC822.SIZE %d", m.Size))
			if up != "FAST" {
				out = append(out, "ENVELOPE "+s.envelope(m))
			}
			if up == "FULL" {
				out = append(out, "BODY "+s.bodyStructure(m, false))
			}
		case up == "UID":
			needUID = true
		case up == "FLAGS":
			out = append(out, "FLAGS ("+strings.Join(m.Flags.IMAPFlags(m.Recent), " ")+")")
		case up == "INTERNALDATE":
			out = append(out, "INTERNALDATE "+quote(m.Internal.Format("02-Jan-2006 15:04:05 -0700")))
		case up == "RFC822.SIZE":
			out = append(out, fmt.Sprintf("RFC822.SIZE %d", m.Size))
		case up == "ENVELOPE":
			out = append(out, "ENVELOPE "+s.envelope(m))
		case up == "BODYSTRUCTURE":
			out = append(out, "BODYSTRUCTURE "+s.bodyStructure(m, true))
		case up == "BODY":
			out = append(out, "BODY "+s.bodyStructure(m, false))
		case up == "RFC822":
			data, _ := m.Read()
			out = append(out, "RFC822 "+literal(string(data)))
			markSeen = true
		case up == "RFC822.HEADER":
			data, _ := m.Read()
			out = append(out, "RFC822.HEADER "+literal(headerOf(data)))
		case up == "RFC822.TEXT":
			data, _ := m.Read()
			out = append(out, "RFC822.TEXT "+literal(bodyOf(data)))
			markSeen = true
		case strings.HasPrefix(up, "BODY.PEEK["):
			section := item[len("BODY.PEEK[") : len(item)-1]
			out = append(out, "BODY["+section+"] "+literal(s.section(m, section)))
		case strings.HasPrefix(up, "BODY["):
			section := item[len("BODY[") : len(item)-1]
			out = append(out, "BODY["+section+"] "+literal(s.section(m, section)))
			markSeen = true
		}
	}
	if needUID {
		out = append(out, fmt.Sprintf("UID %d", m.UID))
	}
	return out, markSeen
}

// splitItems splits a FETCH item list, honoring the brackets and
// parentheses that may contain spaces (BODY[HEADER.FIELDS (A B)]).
func splitItems(spec string) []string {
	spec = strings.TrimSpace(spec)
	spec = strings.TrimPrefix(spec, "(")
	spec = strings.TrimSuffix(spec, ")")

	var items []string
	depth := 0
	start := 0
	for i := 0; i < len(spec); i++ {
		switch spec[i] {
		case '[', '(':
			depth++
		case ']', ')':
			depth--
		case ' ':
			if depth == 0 {
				if i > start {
					items = append(items, spec[start:i])
				}
				start = i + 1
			}
		}
	}
	if start < len(spec) {
		items = append(items, spec[start:])
	}
	return items
}

// section renders a BODY[...] section specifier.
func (s *session) section(m *maildir.Message, section string) string {
	data, err := m.Read()
	if err != nil {
		return ""
	}
	up := strings.ToUpper(strings.TrimSpace(section))
	switch {
	case up == "":
		return string(data)
	case up == "HEADER":
		return headerOf(data)
	case up == "TEXT":
		return bodyOf(data)
	case strings.HasPrefix(up, "HEADER.FIELDS.NOT"):
		return filterHeaders(data, fieldList(section), true)
	case strings.HasPrefix(up, "HEADER.FIELDS"):
		return filterHeaders(data, fieldList(section), false)
	case up == "1":
		// Single-part messages: part 1 is the body.
		return bodyOf(data)
	}
	return ""
}

// fieldList extracts the header names from "HEADER.FIELDS (A B C)".
func fieldList(section string) []string {
	open := strings.Index(section, "(")
	close := strings.LastIndex(section, ")")
	if open < 0 || close <= open {
		return nil
	}
	var out []string
	for _, f := range strings.Fields(section[open+1 : close]) {
		out = append(out, strings.ToLower(strings.Trim(f, `"`)))
	}
	return out
}

// headerOf returns the header block including the blank line.
func headerOf(data []byte) string {
	if i := bytes.Index(data, []byte("\r\n\r\n")); i >= 0 {
		return string(data[:i+4])
	}
	if i := bytes.Index(data, []byte("\n\n")); i >= 0 {
		return string(data[:i+2])
	}
	return string(data)
}

// bodyOf returns everything after the header block.
func bodyOf(data []byte) string {
	if i := bytes.Index(data, []byte("\r\n\r\n")); i >= 0 {
		return string(data[i+4:])
	}
	if i := bytes.Index(data, []byte("\n\n")); i >= 0 {
		return string(data[i+2:])
	}
	return ""
}

// filterHeaders keeps (or drops, when exclude is set) the named
// header fields, preserving continuation lines.
func filterHeaders(data []byte, fields []string, exclude bool) string {
	want := make(map[string]bool, len(fields))
	for _, f := range fields {
		want[f] = true
	}
	var b strings.Builder
	keeping := false
	for _, line := range strings.SplitAfter(headerOf(data), "\n") {
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			continue
		}
		// A continuation line belongs to the previous field.
		if line[0] == ' ' || line[0] == '\t' {
			if keeping {
				b.WriteString(line)
			}
			continue
		}
		name, _, _ := strings.Cut(trimmed, ":")
		keeping = want[strings.ToLower(strings.TrimSpace(name))] != exclude
		if keeping {
			b.WriteString(line)
		}
	}
	b.WriteString("\r\n")
	return b.String()
}

// envelope renders the ENVELOPE structure (RFC 3501 section 7.4.2).
func (s *session) envelope(m *maildir.Message) string {
	data, err := m.Read()
	if err != nil {
		return "NIL"
	}
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return "NIL"
	}
	h := msg.Header
	addrList := func(key string) string {
		list, err := h.AddressList(key)
		if err != nil || len(list) == 0 {
			return "NIL"
		}
		var parts []string
		for _, a := range list {
			local, domain, _ := strings.Cut(a.Address, "@")
			name := "NIL"
			if a.Name != "" {
				name = quote(a.Name)
			}
			parts = append(parts, fmt.Sprintf("(%s NIL %s %s)", name, quote(local), quote(domain)))
		}
		return "(" + strings.Join(parts, "") + ")"
	}
	str := func(v string) string {
		if v == "" {
			return "NIL"
		}
		return quote(v)
	}
	// from is the fallback for sender and reply-to.
	from := addrList("From")
	sender, replyTo := addrList("Sender"), addrList("Reply-To")
	if sender == "NIL" {
		sender = from
	}
	if replyTo == "NIL" {
		replyTo = from
	}
	return fmt.Sprintf("(%s %s %s %s %s %s %s %s %s %s)",
		str(h.Get("Date")), str(h.Get("Subject")),
		from, sender, replyTo,
		addrList("To"), addrList("Cc"), addrList("Bcc"),
		str(h.Get("In-Reply-To")), str(h.Get("Message-ID")))
}

// bodyStructure renders a single-part BODYSTRUCTURE. Kavira does not
// parse MIME trees yet: a multipart message is reported as its
// top-level type, which clients handle by fetching BODY[] and parsing
// it themselves.
func (s *session) bodyStructure(m *maildir.Message, extended bool) string {
	data, err := m.Read()
	if err != nil {
		return "NIL"
	}
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	ctype, subtype, charset := "TEXT", "PLAIN", "US-ASCII"
	encoding := "7BIT"
	if err == nil {
		if ct := msg.Header.Get("Content-Type"); ct != "" {
			mediaType, params := parseContentType(ct)
			if t, st, ok := strings.Cut(mediaType, "/"); ok {
				ctype, subtype = strings.ToUpper(t), strings.ToUpper(st)
			}
			if cs, ok := params["charset"]; ok {
				charset = strings.ToUpper(cs)
			}
		}
		if e := msg.Header.Get("Content-Transfer-Encoding"); e != "" {
			encoding = strings.ToUpper(strings.TrimSpace(e))
		}
	}
	body := bodyOf(data)
	lines := strings.Count(body, "\n")
	base := fmt.Sprintf("(%s %s (%s %s) NIL NIL %s %d %d)",
		quote(ctype), quote(subtype), quote("CHARSET"), quote(charset),
		quote(encoding), len(body), lines)
	return base
}

// parseContentType splits a Content-Type header into media type and
// parameters, without pulling in a full MIME parser.
func parseContentType(v string) (string, map[string]string) {
	parts := strings.Split(v, ";")
	media := strings.ToLower(strings.TrimSpace(parts[0]))
	params := map[string]string{}
	for _, p := range parts[1:] {
		k, val, ok := strings.Cut(p, "=")
		if !ok {
			continue
		}
		params[strings.ToLower(strings.TrimSpace(k))] = strings.Trim(strings.TrimSpace(val), `"`)
	}
	return media, params
}

func (s *session) cmdStore(tag string, p *parser, uidMode bool) {
	s.requireSelected(tag, func() {
		if s.readOnly {
			s.out("%s NO mailbox is read-only", tag)
			return
		}
		setTok, err := p.next()
		if err != nil {
			s.out("%s BAD STORE needs a sequence set", tag)
			return
		}
		set, err := parseSeqSet(setTok.str)
		if err != nil {
			s.out("%s BAD invalid sequence set", tag)
			return
		}
		opTok, err := p.next()
		if err != nil {
			s.out("%s BAD STORE needs an operation", tag)
			return
		}
		op := opTok.upper()
		silent := strings.HasSuffix(op, ".SILENT")
		op = strings.TrimSuffix(op, ".SILENT")

		flagsTok, err := p.next()
		if err != nil {
			s.out("%s BAD STORE needs flags", tag)
			return
		}
		var wanted maildir.Flags
		if flagsTok.isList {
			for _, f := range flagsTok.list {
				if mf, ok := maildir.FlagFromIMAP(f.str); ok {
					wanted = wanted.Add(mf)
				}
			}
		} else if mf, ok := maildir.FlagFromIMAP(flagsTok.str); ok {
			wanted = wanted.Add(mf)
		}

		for _, m := range s.selected(set, uidMode) {
			next := m.Flags
			switch op {
			case "FLAGS":
				next = wanted
			case "+FLAGS":
				for _, f := range wanted {
					next = next.Add(f)
				}
			case "-FLAGS":
				for _, f := range wanted {
					next = next.Remove(f)
				}
			default:
				s.out("%s BAD unknown STORE operation", tag)
				return
			}
			if err := s.mbox.SetFlags(m, next); err != nil {
				s.srv.log.Error("store failed", "protocol", "imap",
					"user", s.user, "uid", m.UID, "error", err.Error())
				continue
			}
			if !silent {
				line := fmt.Sprintf("* %d FETCH (FLAGS (%s)",
					m.Seq, strings.Join(m.Flags.IMAPFlags(m.Recent), " "))
				if uidMode {
					line += fmt.Sprintf(" UID %d", m.UID)
				}
				s.raw(line + ")\r\n")
			}
		}
		s.flush()
		s.out("%s OK STORE completed", tag)
	})
}

func (s *session) cmdCopyMove(tag string, p *parser, uidMode, move bool) {
	name := "COPY"
	if move {
		name = "MOVE"
	}
	s.requireSelected(tag, func() {
		setTok, err := p.next()
		if err != nil {
			s.out("%s BAD %s needs a sequence set", tag, name)
			return
		}
		set, err := parseSeqSet(setTok.str)
		if err != nil {
			s.out("%s BAD invalid sequence set", tag)
			return
		}
		dstTok, err := p.next()
		if err != nil {
			s.out("%s BAD %s needs a destination", tag, name)
			return
		}
		dst := normalizeMailbox(dstTok.str)
		if _, err := maildir.OpenMailbox(s.root, dst); err != nil {
			s.out("%s NO [TRYCREATE] destination does not exist", tag)
			return
		}
		if move && s.readOnly {
			s.out("%s NO mailbox is read-only", tag)
			return
		}

		msgs := s.selected(set, uidMode)
		for _, m := range msgs {
			if err := s.mbox.CopyTo(m, dst); err != nil {
				s.srv.log.Error("copy failed", "protocol", "imap",
					"user", s.user, "uid", m.UID, "error", err.Error())
				s.out("%s NO %s failed", tag, name)
				return
			}
		}
		if move {
			// MOVE is a copy plus an expunge of the sources.
			for _, m := range msgs {
				if err := s.mbox.SetFlags(m, m.Flags.Add(maildir.FlagDeleted)); err != nil {
					s.out("%s NO MOVE failed", tag)
					return
				}
			}
			seqs, err := s.mbox.Expunge()
			if err != nil {
				s.out("%s NO MOVE failed", tag)
				return
			}
			for _, seq := range seqs {
				s.out("* %d EXPUNGE", seq)
			}
		}
		s.out("%s OK %s completed", tag, name)
	})
}

func (s *session) cmdSearch(tag string, p *parser, uidMode bool) {
	s.requireSelected(tag, func() {
		crit, err := p.all()
		if err != nil || len(crit) == 0 {
			s.out("%s BAD SEARCH needs criteria", tag)
			return
		}
		matches := s.search(crit)
		var ids []string
		for _, m := range matches {
			if uidMode {
				ids = append(ids, strconv.FormatUint(uint64(m.UID), 10))
			} else {
				ids = append(ids, strconv.FormatUint(uint64(m.Seq), 10))
			}
		}
		if len(ids) == 0 {
			s.out("* SEARCH")
		} else {
			s.out("* SEARCH %s", strings.Join(ids, " "))
		}
		s.out("%s OK SEARCH completed", tag)
	})
}

// search evaluates the criteria, ANDing them as RFC 3501 requires.
func (s *session) search(crit []token) []*maildir.Message {
	var out []*maildir.Message
	for _, m := range s.mbox.Messages() {
		if s.matches(m, crit) {
			out = append(out, m)
		}
	}
	return out
}

// matches evaluates every criterion against one message.
func (s *session) matches(m *maildir.Message, crit []token) bool {
	var data []byte
	load := func() []byte {
		if data == nil {
			data, _ = m.Read()
		}
		return data
	}

	for i := 0; i < len(crit); i++ {
		key := crit[i].upper()
		// arg fetches the i+1'th token as this criterion's argument.
		arg := func() string {
			if i+1 < len(crit) {
				i++
				return crit[i].str
			}
			return ""
		}
		switch key {
		case "ALL":
		case "ANSWERED":
			if !m.Flags.Has(maildir.FlagAnswered) {
				return false
			}
		case "UNANSWERED":
			if m.Flags.Has(maildir.FlagAnswered) {
				return false
			}
		case "DELETED":
			if !m.Flags.Has(maildir.FlagDeleted) {
				return false
			}
		case "UNDELETED":
			if m.Flags.Has(maildir.FlagDeleted) {
				return false
			}
		case "DRAFT":
			if !m.Flags.Has(maildir.FlagDraft) {
				return false
			}
		case "UNDRAFT":
			if m.Flags.Has(maildir.FlagDraft) {
				return false
			}
		case "FLAGGED":
			if !m.Flags.Has(maildir.FlagFlagged) {
				return false
			}
		case "UNFLAGGED":
			if m.Flags.Has(maildir.FlagFlagged) {
				return false
			}
		case "SEEN":
			if !m.Flags.Has(maildir.FlagSeen) {
				return false
			}
		case "UNSEEN":
			if m.Flags.Has(maildir.FlagSeen) {
				return false
			}
		case "NEW":
			if !m.Recent || m.Flags.Has(maildir.FlagSeen) {
				return false
			}
		case "OLD":
			if m.Recent {
				return false
			}
		case "RECENT":
			if !m.Recent {
				return false
			}
		case "FROM", "TO", "CC", "BCC", "SUBJECT":
			if !containsHeader(load(), key, arg()) {
				return false
			}
		case "HEADER":
			name := arg()
			value := arg()
			if !containsHeader(load(), name, value) {
				return false
			}
		case "BODY":
			if !strings.Contains(strings.ToLower(bodyOf(load())), strings.ToLower(arg())) {
				return false
			}
		case "TEXT":
			if !strings.Contains(strings.ToLower(string(load())), strings.ToLower(arg())) {
				return false
			}
		case "LARGER":
			n, _ := strconv.ParseInt(arg(), 10, 64)
			if m.Size <= n {
				return false
			}
		case "SMALLER":
			n, _ := strconv.ParseInt(arg(), 10, 64)
			if m.Size >= n {
				return false
			}
		case "BEFORE", "SINCE", "ON":
			d, err := time.Parse("02-Jan-2006", strings.Trim(arg(), `"`))
			if err != nil {
				return false
			}
			mt := m.Internal.Truncate(24 * time.Hour)
			switch key {
			case "BEFORE":
				if !mt.Before(d) {
					return false
				}
			case "SINCE":
				if mt.Before(d) {
					return false
				}
			case "ON":
				if !sameDay(m.Internal, d) {
					return false
				}
			}
		case "UID":
			set, err := parseSeqSet(arg())
			if err != nil {
				return false
			}
			msgs := s.mbox.Messages()
			var max uint32
			if n := len(msgs); n > 0 {
				max = msgs[n-1].UID
			}
			if !set.contains(m.UID, max) {
				return false
			}
		case "NOT":
			// Negate exactly the next criterion.
			if i+1 < len(crit) {
				i++
				if s.matches(m, []token{crit[i]}) {
					return false
				}
			}
		default:
			// A bare sequence set is a valid criterion.
			if set, err := parseSeqSet(crit[i].str); err == nil {
				if !set.contains(m.Seq, uint32(s.mbox.Count())) {
					return false
				}
			}
		}
	}
	return true
}

func sameDay(a, b time.Time) bool {
	ay, am, ad := a.Date()
	by, bm, bd := b.Date()
	return ay == by && am == bm && ad == bd
}

// containsHeader reports whether a header field contains a substring,
// case-insensitively (IMAP SEARCH semantics).
func containsHeader(data []byte, name, value string) bool {
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return false
	}
	got := msg.Header.Get(name)
	if value == "" {
		return got != ""
	}
	return strings.Contains(strings.ToLower(got), strings.ToLower(value))
}
