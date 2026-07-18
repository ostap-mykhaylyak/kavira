// Package mailauth runs the inbound authentication pipeline on port
// 25: SPF (RFC 7208), DKIM verification (RFC 6376) and DMARC
// (RFC 7489) with relaxed/strict alignment on the organizational
// domain.
//
// The verdict maps straight onto SMTP behavior: Reject answers 550 at
// DATA, Quarantine delivers into the Spam folder, Accept delivers
// normally. Every checked message gets an Authentication-Results
// header so users and downstream filters can see what happened. A
// DNS temporary failure during DMARC evaluation degrades to Accept:
// losing mail over a flaky resolver is worse than delivering it.
package mailauth

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"net"
	"net/mail"
	"strings"

	"blitiri.com.ar/go/spf"
	msgdkim "github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-msgauth/dmarc"
	"golang.org/x/net/publicsuffix"
)

// Action is the disposition of a checked message.
type Action int

const (
	Accept Action = iota
	Quarantine
	Reject
)

// Result is the outcome of the pipeline for one message.
type Result struct {
	Action Action
	// Reason explains a non-Accept action (SMTP reply text, logs).
	Reason string
	// AuthResults is the complete Authentication-Results header
	// (CRLF-terminated) to prepend to the message.
	AuthResults string
	// SPF/DKIM/DMARC carry the individual verdicts for logging.
	SPF   string
	DKIM  string
	DMARC string
}

// Checker evaluates inbound messages. The zero value is not usable:
// build it with New.
type Checker struct {
	// Hostname is the authserv-id in Authentication-Results.
	Hostname string
	// Enforce applies DMARC reject/quarantine. When false the
	// pipeline only annotates (p=none behavior for everyone).
	Enforce bool
	// LookupTXT overrides DNS TXT lookups (tests). Nil = net.LookupTXT.
	LookupTXT func(name string) ([]string, error)
	// SPFResolver overrides the SPF resolver (tests). Nil = default.
	SPFResolver spf.DNSResolver
}

// New builds a Checker with real DNS.
func New(hostname string, enforce bool) *Checker {
	return &Checker{Hostname: hostname, Enforce: enforce}
}

// dkimOutcome is one verified signature.
type dkimOutcome struct {
	domain string
	pass   bool
}

// Check runs SPF, DKIM and DMARC for a message received from ip with
// the given HELO name and envelope sender.
func (c *Checker) Check(ip net.IP, helo, mailFrom string, data []byte) Result {
	// --- SPF ---
	sender := mailFrom
	if sender == "" {
		// RFC 7208 section 2.4: null reverse-path checks HELO.
		sender = "postmaster@" + helo
	}
	spfOpts := []spf.Option{}
	if c.SPFResolver != nil {
		spfOpts = append(spfOpts, spf.WithResolver(c.SPFResolver))
	}
	spfResult, _ := spf.CheckHostWithSender(ip, helo, sender, spfOpts...)
	spfDomain := domainOf(sender)

	// --- DKIM ---
	var dkims []dkimOutcome
	verifs, err := msgdkim.VerifyWithOptions(bytes.NewReader(data), &msgdkim.VerifyOptions{
		LookupTXT:        c.LookupTXT,
		MaxVerifications: 8,
	})
	if err == nil {
		for _, v := range verifs {
			dkims = append(dkims, dkimOutcome{domain: strings.ToLower(v.Domain), pass: v.Err == nil})
		}
	}

	// --- DMARC ---
	fromDomain := headerFromDomain(data)
	dmarcResult, policy := c.evaluateDMARC(fromDomain, spfDomain, string(spfResult), dkims)

	res := Result{
		SPF:         string(spfResult),
		DKIM:        dkimSummary(dkims),
		DMARC:       dmarcResult,
		AuthResults: c.authResults(spfResult, spfDomain, dkims, dmarcResult, fromDomain),
	}

	if dmarcResult == "fail" && c.Enforce {
		switch policy {
		case dmarc.PolicyReject:
			res.Action = Reject
			res.Reason = fmt.Sprintf("DMARC policy reject for %s", fromDomain)
		case dmarc.PolicyQuarantine:
			res.Action = Quarantine
			res.Reason = fmt.Sprintf("DMARC policy quarantine for %s", fromDomain)
		}
	}
	return res
}

// evaluateDMARC returns "pass", "fail" or "none" plus the applicable
// policy.
func (c *Checker) evaluateDMARC(fromDomain, spfDomain, spfResult string, dkims []dkimOutcome) (string, dmarc.Policy) {
	if fromDomain == "" {
		return "none", dmarc.PolicyNone
	}
	rec, usedOrg := c.lookupDMARC(fromDomain)
	if rec == nil {
		return "none", dmarc.PolicyNone
	}

	// Identifier alignment (RFC 7489 section 3.1).
	spfAligned := spfResult == "pass" && aligned(spfDomain, fromDomain, rec.SPFAlignment)
	dkimAligned := false
	for _, d := range dkims {
		if d.pass && aligned(d.domain, fromDomain, rec.DKIMAlignment) {
			dkimAligned = true
			break
		}
	}
	if spfAligned || dkimAligned {
		return "pass", rec.Policy
	}

	policy := rec.Policy
	// A subdomain matched via the org domain record may carry its own
	// subdomain policy.
	if usedOrg && rec.SubdomainPolicy != "" {
		policy = rec.SubdomainPolicy
	}
	// pct= samples enforcement; unsampled messages degrade one level.
	if rec.Percent != nil && *rec.Percent < 100 && rand.IntN(100) >= *rec.Percent {
		if policy == dmarc.PolicyReject {
			policy = dmarc.PolicyQuarantine
		} else {
			policy = dmarc.PolicyNone
		}
	}
	return "fail", policy
}

// lookupDMARC fetches the record for domain, falling back to the
// organizational domain. usedOrg reports which record answered.
func (c *Checker) lookupDMARC(domain string) (rec *dmarc.Record, usedOrg bool) {
	opts := &dmarc.LookupOptions{LookupTXT: c.LookupTXT}
	if r, err := dmarc.LookupWithOptions(domain, opts); err == nil {
		return r, false
	}
	org := orgDomain(domain)
	if org == domain {
		return nil, false
	}
	if r, err := dmarc.LookupWithOptions(org, opts); err == nil {
		return r, true
	}
	return nil, false
}

// aligned checks identifier alignment: strict wants an exact domain
// match, relaxed (the default) compares organizational domains.
func aligned(d, fromDomain string, mode dmarc.AlignmentMode) bool {
	d, fromDomain = strings.ToLower(d), strings.ToLower(fromDomain)
	if d == fromDomain {
		return true
	}
	if mode == dmarc.AlignmentStrict {
		return false
	}
	return orgDomain(d) == orgDomain(fromDomain)
}

// orgDomain returns the organizational domain per the public suffix
// list (studenti.ente.it -> ente.it is wrong for DMARC: the org
// domain of a.b.example.co.uk is example.co.uk).
func orgDomain(d string) string {
	org, err := publicsuffix.EffectiveTLDPlusOne(d)
	if err != nil {
		return d
	}
	return org
}

// headerFromDomain extracts the domain of the RFC 5322 From header.
// Missing, unparsable or multi-address From yields "" (no DMARC
// evaluation; the antispam layer of M5 scores those separately).
func headerFromDomain(data []byte) string {
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return ""
	}
	addrs, err := msg.Header.AddressList("From")
	if err != nil || len(addrs) != 1 {
		return ""
	}
	return domainOf(addrs[0].Address)
}

func domainOf(addr string) string {
	at := strings.LastIndex(addr, "@")
	if at < 0 || at == len(addr)-1 {
		return ""
	}
	return strings.ToLower(addr[at+1:])
}

func dkimSummary(dkims []dkimOutcome) string {
	if len(dkims) == 0 {
		return "none"
	}
	for _, d := range dkims {
		if d.pass {
			return "pass"
		}
	}
	return "fail"
}

// authResults renders the Authentication-Results header (RFC 8601).
func (c *Checker) authResults(spfRes spf.Result, spfDomain string, dkims []dkimOutcome, dmarcRes, fromDomain string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Authentication-Results: %s;\r\n\tspf=%s smtp.mailfrom=%s", c.Hostname, spfRes, spfDomain)
	if len(dkims) == 0 {
		b.WriteString(";\r\n\tdkim=none")
	}
	for _, d := range dkims {
		verdict := "fail"
		if d.pass {
			verdict = "pass"
		}
		fmt.Fprintf(&b, ";\r\n\tdkim=%s header.d=%s", verdict, d.domain)
	}
	if fromDomain != "" {
		fmt.Fprintf(&b, ";\r\n\tdmarc=%s header.from=%s", dmarcRes, fromDomain)
	}
	b.WriteString("\r\n")
	return b.String()
}
