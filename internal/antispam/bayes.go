// Package antispam scores inbound messages: a Bayesian classifier
// trained on the operator's own corpus, plus heuristic rules over the
// headers, the URIs and the attachments.
//
// The score is a spam probability in 0..100. The SMTP layer turns it
// into a disposition through two configurable thresholds, so the
// policy (tag, quarantine, reject) stays out of the classifier.
package antispam

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"
)

// Bayesian tuning constants (Graham's "A Plan for Spam", with the
// usual refinements).
const (
	// minTokenLen and maxTokenLen bound what counts as a token.
	minTokenLen = 3
	maxTokenLen = 24
	// significant is how many of the most decisive tokens are
	// combined into the final probability.
	significant = 15
	// minOccurrences is how often a token must have been seen before
	// it is trusted at all.
	minOccurrences = 3
	// unknownProb is the probability assigned to a token the corpus
	// has never seen: deliberately neutral-to-hammy, so novel
	// vocabulary alone cannot condemn a message.
	unknownProb = 0.4
	// probFloor and probCeil keep any single token from dominating.
	probFloor = 0.01
	probCeil  = 0.99
)

// counts is the per-token training data.
type counts struct {
	Ham  uint32
	Spam uint32
}

// Bayes is a persistent naive Bayes classifier over message tokens.
// It is safe for concurrent use.
type Bayes struct {
	mu     sync.RWMutex
	path   string
	tokens map[string]*counts
	nHam   uint32
	nSpam  uint32
	dirty  bool
}

// NewBayes loads the corpus at path, or starts an empty one.
func NewBayes(path string) (*Bayes, error) {
	b := &Bayes{path: path, tokens: map[string]*counts{}}
	if path == "" {
		return b, nil
	}
	if err := b.load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return b, nil
}

// Trained reports how many messages of each class were learned.
func (b *Bayes) Trained() (ham, spam uint32) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.nHam, b.nSpam
}

// Ready reports whether the corpus holds enough examples to classify.
// Below this, Score returns "no opinion" rather than guessing from a
// handful of messages.
func (b *Bayes) Ready() bool {
	ham, spam := b.Trained()
	return ham >= 20 && spam >= 20
}

// Train learns one message as ham or spam.
func (b *Bayes) Train(data []byte, isSpam bool) {
	toks := Tokenize(data)
	b.mu.Lock()
	defer b.mu.Unlock()
	for tok := range toks {
		c := b.tokens[tok]
		if c == nil {
			c = &counts{}
			b.tokens[tok] = c
		}
		if isSpam {
			c.Spam++
		} else {
			c.Ham++
		}
	}
	if isSpam {
		b.nSpam++
	} else {
		b.nHam++
	}
	b.dirty = true
}

// Score returns the spam probability of a message in 0..1, and
// whether the classifier had an opinion at all.
func (b *Bayes) Score(data []byte) (float64, bool) {
	if !b.Ready() {
		return 0, false
	}
	toks := Tokenize(data)

	b.mu.RLock()
	nHam, nSpam := float64(b.nHam), float64(b.nSpam)
	type scored struct {
		prob float64
		dist float64
	}
	var list []scored
	for tok := range toks {
		c := b.tokens[tok]
		p := unknownProb
		if c != nil && c.Ham+c.Spam >= minOccurrences {
			// Ham counts are doubled: a false positive costs the user
			// far more than a false negative, so evidence of ham
			// weighs heavier (Graham's bias).
			g := math.Min(1, float64(c.Ham)*2/math.Max(nHam, 1))
			s := math.Min(1, float64(c.Spam)/math.Max(nSpam, 1))
			if g+s > 0 {
				p = s / (g + s)
			}
			p = math.Max(probFloor, math.Min(probCeil, p))
		}
		list = append(list, scored{prob: p, dist: math.Abs(p - 0.5)})
	}
	b.mu.RUnlock()

	if len(list) == 0 {
		return 0, false
	}
	// Keep only the most decisive tokens.
	sort.Slice(list, func(i, j int) bool { return list[i].dist > list[j].dist })
	if len(list) > significant {
		list = list[:significant]
	}

	// Combine in log space: multiplying many small probabilities
	// underflows to zero and silently classifies everything as ham.
	var logSpam, logHam float64
	for _, s := range list {
		logSpam += math.Log(s.prob)
		logHam += math.Log(1 - s.prob)
	}
	// p = e^logSpam / (e^logSpam + e^logHam), computed stably.
	maxLog := math.Max(logSpam, logHam)
	es, eh := math.Exp(logSpam-maxLog), math.Exp(logHam-maxLog)
	return es / (es + eh), true
}

// Tokenize extracts the feature set of a message. Header fields that
// carry signal are prefixed so "free" in a Subject is a different
// feature from "free" in the body.
func Tokenize(data []byte) map[string]bool {
	out := map[string]bool{}
	text := string(data)

	header, body, found := strings.Cut(text, "\r\n\r\n")
	if !found {
		header, body, _ = strings.Cut(text, "\n\n")
	}

	for _, line := range strings.Split(header, "\n") {
		line = strings.TrimRight(line, "\r")
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "subject", "from", "to", "reply-to", "content-type", "x-mailer", "list-unsubscribe":
			prefix := strings.ToLower(strings.TrimSpace(name)) + "*"
			for _, t := range words(value) {
				out[prefix+t] = true
			}
		}
	}
	for _, t := range words(body) {
		out[t] = true
	}
	return out
}

// words splits text into normalized tokens.
func words(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool {
		// Keep the characters that carry signal inside a token:
		// currency symbols, digits and the pieces of a domain.
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) &&
			r != '$' && r != '\'' && r != '-' && r != '.' && r != '!'
	}) {
		f = strings.Trim(strings.ToLower(f), ".-'!")
		if len(f) < minTokenLen || len(f) > maxTokenLen {
			continue
		}
		out = append(out, f)
	}
	return out
}

// Save persists the corpus if it changed since the last write.
func (b *Bayes) Save() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.dirty || b.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(b.path), 0o700); err != nil {
		return err
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "H%d S%d\n", b.nHam, b.nSpam)
	// Sorted so the file is stable and diffable between saves.
	keys := make([]string, 0, len(b.tokens))
	for k := range b.tokens {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		c := b.tokens[k]
		fmt.Fprintf(&sb, "%d %d %s\n", c.Ham, c.Spam, k)
	}

	tmp := b.path + ".tmp"
	if err := os.WriteFile(tmp, []byte(sb.String()), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, b.path); err != nil {
		os.Remove(tmp)
		return err
	}
	b.dirty = false
	return nil
}

// load reads a corpus written by Save.
func (b *Bayes) load() error {
	f, err := os.Open(b.path)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	if !sc.Scan() {
		return nil
	}
	header := strings.Fields(sc.Text())
	if len(header) != 2 || !strings.HasPrefix(header[0], "H") || !strings.HasPrefix(header[1], "S") {
		return fmt.Errorf("bayes corpus %s: bad header", b.path)
	}
	nHam, err1 := strconv.ParseUint(header[0][1:], 10, 32)
	nSpam, err2 := strconv.ParseUint(header[1][1:], 10, 32)
	if err1 != nil || err2 != nil {
		return fmt.Errorf("bayes corpus %s: bad header counts", b.path)
	}
	b.nHam, b.nSpam = uint32(nHam), uint32(nSpam)

	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), " ", 3)
		if len(parts) != 3 {
			continue
		}
		h, err1 := strconv.ParseUint(parts[0], 10, 32)
		s, err2 := strconv.ParseUint(parts[1], 10, 32)
		if err1 != nil || err2 != nil {
			continue
		}
		b.tokens[parts[2]] = &counts{Ham: uint32(h), Spam: uint32(s)}
	}
	return sc.Err()
}
