package antispam

import (
	"fmt"
	"strings"
)

// Verdict is what the engine concluded about a message.
type Verdict struct {
	// Score is the spam score in 0..100.
	Score float64
	// Rules lists the heuristics that fired, for the log and the
	// X-Spam-Status header.
	Rules []string
	// Virus names the malware found, empty when clean.
	Virus string
	// BadAttachment names a refused executable attachment.
	BadAttachment string
	// Bayes is the classifier probability, -1 when it had no opinion.
	Bayes float64
}

// Header renders the X-Spam-Status header line for the message.
func (v Verdict) Header(threshold float64) string {
	state := "No"
	if v.Score >= threshold {
		state = "Yes"
	}
	line := fmt.Sprintf("X-Spam-Status: %s, score=%.1f required=%.1f",
		state, v.Score, threshold)
	if len(v.Rules) > 0 {
		line += " tests=" + strings.Join(v.Rules, ",")
	}
	return line + "\r\n"
}

// Scanner checks a message for malware (ClamAV). A nil Scanner
// disables antivirus.
type Scanner interface {
	// Scan returns the malware name, or "" when the message is clean.
	Scan(data []byte) (string, error)
}

// Lister answers URI blacklist questions. A nil Lister disables URIBL.
type Lister interface {
	// ListedDomain reports whether a hostname is blacklisted.
	ListedDomain(domain string) bool
}

// Engine combines the Bayesian classifier, the heuristics, the URI
// blacklists and the antivirus into one score.
type Engine struct {
	Bayes   *Bayes
	Scanner Scanner
	URIBL   Lister
	// BayesWeight is how many points a fully-confident Bayesian spam
	// verdict contributes. The heuristics supply the rest.
	BayesWeight float64
}

// Check scores one message.
func (e *Engine) Check(data []byte) Verdict {
	v := Verdict{Bayes: -1}

	analysis := AnalyzeHeaders(data)
	v.Score = analysis.Total()
	v.Rules = analysis.Names()
	v.BadAttachment = analysis.BadAttachment

	// URI blacklists: a listed link is strong evidence, since the
	// payload of most spam is the link itself.
	if e.URIBL != nil {
		seen := map[string]bool{}
		for _, d := range analysis.URIDomains {
			if seen[d] {
				continue
			}
			seen[d] = true
			if e.URIBL.ListedDomain(d) {
				v.Score += 25
				v.Rules = append(v.Rules, "URIBL_LISTED")
				break // one listing is enough; do not stack them
			}
		}
	}

	// Bayesian contribution, only when the corpus is trained enough.
	if e.Bayes != nil {
		if p, ok := e.Bayes.Score(data); ok {
			v.Bayes = p
			weight := e.BayesWeight
			if weight == 0 {
				weight = 60
			}
			// Center on 0.5: a neutral classifier adds nothing, and a
			// confident ham verdict actively pulls the score down.
			v.Score += (p - 0.5) * 2 * weight
			switch {
			case p >= 0.9:
				v.Rules = append(v.Rules, "BAYES_99")
			case p >= 0.7:
				v.Rules = append(v.Rules, "BAYES_80")
			case p <= 0.1:
				v.Rules = append(v.Rules, "BAYES_00")
			}
		}
	}

	// Antivirus is decisive: a positive hit overrides every score.
	if e.Scanner != nil {
		if name, err := e.Scanner.Scan(data); err == nil && name != "" {
			v.Virus = name
			v.Rules = append(v.Rules, "VIRUS_FOUND")
			v.Score = 100
		}
	}

	if v.Score < 0 {
		v.Score = 0
	}
	if v.Score > 100 {
		v.Score = 100
	}
	return v
}
