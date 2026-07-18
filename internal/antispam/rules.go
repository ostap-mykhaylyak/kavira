package antispam

import (
	"bytes"
	"net/mail"
	"path/filepath"
	"regexp"
	"strings"
)

// Rule is one heuristic finding: a name for the log and a score
// contribution in points (positive = spammier, negative = hammier).
type Rule struct {
	Name  string
	Score float64
}

// executableExtensions are attachment types that are refused outright
// rather than scored: no legitimate mail needs to carry them, and a
// user only has to click once.
var executableExtensions = map[string]bool{
	".exe": true, ".scr": true, ".pif": true, ".com": true, ".bat": true,
	".cmd": true, ".vbs": true, ".vbe": true, ".js": true, ".jse": true,
	".wsf": true, ".wsh": true, ".msi": true, ".jar": true, ".lnk": true,
	".ps1": true, ".hta": true, ".cpl": true, ".msc": true, ".reg": true,
}

var (
	reURL        = regexp.MustCompile(`(?i)https?://([a-z0-9.-]+)`)
	reFilename   = regexp.MustCompile(`(?i)(?:filename|name)\s*=\s*"?([^";\r\n]+)"?`)
	reIPLiteral  = regexp.MustCompile(`https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
	reManyExcl   = regexp.MustCompile(`!{3,}`)
	reObfuscated = regexp.MustCompile(`(?i)\b[a-z]\s+[a-z]\s+[a-z]\s+[a-z]\s+[a-z]\b`)
)

// Analysis is the outcome of the heuristic pass.
type Analysis struct {
	Rules []Rule
	// URIDomains are the hostnames found in the body, for URIBL.
	URIDomains []string
	// BadAttachment names an executable attachment, if any.
	BadAttachment string
}

// Total sums the rule scores.
func (a Analysis) Total() float64 {
	var t float64
	for _, r := range a.Rules {
		t += r.Score
	}
	return t
}

// Names lists the triggered rules, for logging.
func (a Analysis) Names() []string {
	out := make([]string, 0, len(a.Rules))
	for _, r := range a.Rules {
		out = append(out, r.Name)
	}
	return out
}

// AnalyzeHeaders applies the header and body heuristics.
func AnalyzeHeaders(data []byte) Analysis {
	var a Analysis
	add := func(name string, score float64) {
		a.Rules = append(a.Rules, Rule{Name: name, Score: score})
	}

	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		// A message whose headers do not parse is either broken or
		// deliberately malformed; both are suspicious.
		add("MALFORMED_HEADERS", 15)
		return a
	}
	h := msg.Header

	// --- structural header checks ---
	if h.Get("Message-ID") == "" {
		add("NO_MESSAGE_ID", 8)
	}
	if h.Get("Date") == "" {
		add("NO_DATE", 5)
	}
	from := h.Get("From")
	if from == "" {
		add("NO_FROM", 12)
	}
	if h.Get("To") == "" && h.Get("Cc") == "" {
		// Undisclosed recipients is a bulk-mail signature.
		add("NO_RECIPIENT_HEADER", 6)
	}
	if strings.Count(from, "@") > 1 {
		add("MULTIPLE_FROM_ADDRESSES", 10)
	}
	// A display name that itself looks like a different address is the
	// classic phishing disguise.
	if addrs, err := h.AddressList("From"); err == nil && len(addrs) == 1 {
		name := addrs[0].Name
		if strings.Contains(name, "@") && !strings.EqualFold(name, addrs[0].Address) {
			add("FROM_DISPLAY_NAME_SPOOF", 20)
		}
	}

	subject := h.Get("Subject")
	if subject == "" {
		add("NO_SUBJECT", 4)
	} else {
		if isShouty(subject) {
			add("SUBJECT_ALL_CAPS", 6)
		}
		if reManyExcl.MatchString(subject) {
			add("SUBJECT_EXCESS_EXCLAMATION", 5)
		}
	}

	// --- body checks ---
	body := bodyOf(data)
	lower := strings.ToLower(body)

	for _, m := range reURL.FindAllStringSubmatch(body, -1) {
		a.URIDomains = append(a.URIDomains, strings.ToLower(strings.TrimSuffix(m[1], ".")))
	}
	if len(a.URIDomains) > 20 {
		add("EXCESSIVE_LINKS", 6)
	}
	if reIPLiteral.MatchString(body) {
		add("URL_IS_RAW_IP", 12)
	}
	if reObfuscated.MatchString(body) {
		add("SPACED_OUT_TEXT", 8)
	}
	if len(body) > 0 && isShouty(body) {
		add("BODY_ALL_CAPS", 5)
	}

	// A text part that is nothing but a link is a common lure.
	if trimmed := strings.TrimSpace(lower); len(a.URIDomains) > 0 && len(trimmed) < 200 {
		add("SHORT_BODY_WITH_LINK", 5)
	}

	// --- attachments ---
	for _, m := range reFilename.FindAllStringSubmatch(string(data), -1) {
		name := strings.TrimSpace(m[1])
		ext := strings.ToLower(filepath.Ext(name))
		if executableExtensions[ext] {
			a.BadAttachment = name
			add("EXECUTABLE_ATTACHMENT", 50)
			// "fattura.pdf.exe": a harmless-looking extension in front
			// of the real one, so a client hiding known extensions
			// shows the user only "fattura.pdf".
			if base := strings.TrimSuffix(name, filepath.Ext(name)); filepath.Ext(base) != "" {
				add("DOUBLE_EXTENSION", 30)
			}
		}
	}

	return a
}

// isShouty reports whether text is mostly upper case, ignoring short
// strings where capitalization means nothing.
func isShouty(s string) bool {
	var letters, upper int
	for _, r := range s {
		if r >= 'a' && r <= 'z' {
			letters++
		} else if r >= 'A' && r <= 'Z' {
			letters++
			upper++
		}
	}
	return letters >= 12 && float64(upper)/float64(letters) > 0.75
}

// bodyOf returns the message body.
func bodyOf(data []byte) string {
	if i := bytes.Index(data, []byte("\r\n\r\n")); i >= 0 {
		return string(data[i+4:])
	}
	if i := bytes.Index(data, []byte("\n\n")); i >= 0 {
		return string(data[i+2:])
	}
	return ""
}
