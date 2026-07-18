package mailauth

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/ostap-mykhaylyak/kavira/internal/dkim"
)

// stubDNS answers TXT lookups from a map and serves as both the DKIM
// / DMARC LookupTXT and the SPF resolver.
type stubDNS struct {
	txt map[string][]string
}

func (s *stubDNS) lookupTXT(name string) ([]string, error) {
	name = strings.TrimSuffix(name, ".")
	if v, ok := s.txt[name]; ok {
		return v, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (s *stubDNS) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return s.lookupTXT(name)
}
func (s *stubDNS) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}
func (s *stubDNS) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}
func (s *stubDNS) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
}

func checker(dns *stubDNS) *Checker {
	return &Checker{
		Hostname:    "mail.example.com",
		Enforce:     true,
		LookupTXT:   dns.lookupTXT,
		SPFResolver: dns,
	}
}

const plainMsg = "From: news@sender.org\r\n" +
	"To: admin@example.com\r\n" +
	"Subject: ciao\r\n" +
	"\r\n" +
	"testo\r\n"

func TestSPFPassDMARCAligned(t *testing.T) {
	dns := &stubDNS{txt: map[string][]string{
		"sender.org":        {"v=spf1 ip4:198.51.100.7 -all"},
		"_dmarc.sender.org": {"v=DMARC1; p=reject"},
	}}
	res := checker(dns).Check(net.ParseIP("198.51.100.7"), "mx.sender.org", "news@sender.org", []byte(plainMsg))

	if res.Action != Accept {
		t.Fatalf("action = %v, reason %q", res.Action, res.Reason)
	}
	if res.SPF != "pass" || res.DMARC != "pass" {
		t.Errorf("spf=%s dmarc=%s", res.SPF, res.DMARC)
	}
	for _, want := range []string{"Authentication-Results: mail.example.com", "spf=pass", "dmarc=pass header.from=sender.org"} {
		if !strings.Contains(res.AuthResults, want) {
			t.Errorf("AuthResults missing %q:\n%s", want, res.AuthResults)
		}
	}
}

func TestSPFFailDMARCReject(t *testing.T) {
	dns := &stubDNS{txt: map[string][]string{
		"sender.org":        {"v=spf1 ip4:198.51.100.7 -all"},
		"_dmarc.sender.org": {"v=DMARC1; p=reject"},
	}}
	// Spoofed source IP.
	res := checker(dns).Check(net.ParseIP("203.0.113.99"), "evil.example.net", "news@sender.org", []byte(plainMsg))

	if res.Action != Reject {
		t.Fatalf("want Reject, got %v (spf=%s dmarc=%s)", res.Action, res.SPF, res.DMARC)
	}
	if !strings.Contains(res.Reason, "sender.org") {
		t.Errorf("reason = %q", res.Reason)
	}
}

func TestDMARCQuarantine(t *testing.T) {
	dns := &stubDNS{txt: map[string][]string{
		"sender.org":        {"v=spf1 ip4:198.51.100.7 -all"},
		"_dmarc.sender.org": {"v=DMARC1; p=quarantine"},
	}}
	res := checker(dns).Check(net.ParseIP("203.0.113.99"), "x.net", "news@sender.org", []byte(plainMsg))
	if res.Action != Quarantine {
		t.Fatalf("want Quarantine, got %v", res.Action)
	}
}

func TestNoDMARCRecordAccepts(t *testing.T) {
	dns := &stubDNS{txt: map[string][]string{
		"sender.org": {"v=spf1 -all"},
	}}
	res := checker(dns).Check(net.ParseIP("203.0.113.99"), "x.net", "news@sender.org", []byte(plainMsg))
	if res.Action != Accept {
		t.Fatalf("no DMARC record must accept, got %v", res.Action)
	}
	if res.DMARC != "none" {
		t.Errorf("dmarc = %s", res.DMARC)
	}
}

func TestEnforceOffOnlyAnnotates(t *testing.T) {
	dns := &stubDNS{txt: map[string][]string{
		"sender.org":        {"v=spf1 -all"},
		"_dmarc.sender.org": {"v=DMARC1; p=reject"},
	}}
	c := checker(dns)
	c.Enforce = false
	res := c.Check(net.ParseIP("203.0.113.99"), "x.net", "news@sender.org", []byte(plainMsg))
	if res.Action != Accept {
		t.Fatalf("enforce off must accept, got %v", res.Action)
	}
	if res.DMARC != "fail" {
		t.Errorf("dmarc should still record fail, got %s", res.DMARC)
	}
}

func TestDKIMAlignedPassSavesDMARC(t *testing.T) {
	// Sign a message with a fresh key for sender.org, publish the
	// record in the stub, fail SPF: DKIM alignment alone must pass
	// DMARC.
	dir := t.TempDir()
	name, value, err := dkim.Generate(dir, "sender.org", "")
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := dkim.NewStore(dir).Signer("sender.org", "")
	signed, err := dkim.Sign([]byte(plainMsg), "sender.org", "", signer)
	if err != nil {
		t.Fatal(err)
	}

	dns := &stubDNS{txt: map[string][]string{
		"sender.org":        {"v=spf1 ip4:198.51.100.7 -all"}, // SPF will fail
		"_dmarc.sender.org": {"v=DMARC1; p=reject"},
		name:                {value},
	}}
	res := checker(dns).Check(net.ParseIP("203.0.113.99"), "relay.other.net", "news@sender.org", signed)

	if res.Action != Accept {
		t.Fatalf("aligned DKIM should save DMARC: %v (dkim=%s dmarc=%s)", res.Action, res.DKIM, res.DMARC)
	}
	if res.SPF == "pass" || res.DKIM != "pass" || res.DMARC != "pass" {
		t.Errorf("spf=%s dkim=%s dmarc=%s", res.SPF, res.DKIM, res.DMARC)
	}
	if !strings.Contains(res.AuthResults, "dkim=pass header.d=sender.org") {
		t.Errorf("AuthResults:\n%s", res.AuthResults)
	}
}

func TestOrgDomainAlignment(t *testing.T) {
	// Envelope mail from mailer.newsletter.sender.org, From header
	// sender.org: relaxed alignment via the organizational domain.
	dns := &stubDNS{txt: map[string][]string{
		"newsletter.sender.org": {"v=spf1 ip4:198.51.100.7 -all"},
		"_dmarc.sender.org":     {"v=DMARC1; p=reject"},
	}}
	res := checker(dns).Check(net.ParseIP("198.51.100.7"), "mx.newsletter.sender.org",
		"bounce@newsletter.sender.org", []byte(plainMsg))
	if res.DMARC != "pass" {
		t.Fatalf("relaxed alignment must pass via org domain: dmarc=%s spf=%s", res.DMARC, res.SPF)
	}
}

func TestNullSenderUsesHelo(t *testing.T) {
	dns := &stubDNS{txt: map[string][]string{
		"bounces.sender.org": {"v=spf1 ip4:198.51.100.7 -all"},
	}}
	res := checker(dns).Check(net.ParseIP("198.51.100.7"), "bounces.sender.org", "", []byte(plainMsg))
	if res.SPF != "pass" {
		t.Fatalf("null sender should check HELO: spf=%s", res.SPF)
	}
}

func TestHeaderFromDomain(t *testing.T) {
	cases := map[string]string{
		plainMsg: "sender.org",
		"From: \"Nome Cognome\" <a@b.example.org>\r\n\r\nx":     "b.example.org",
		"Subject: no from\r\n\r\nx":                             "",
		"From: a@x.org\r\nFrom broken\r\n\r\n":                  "",
		"From: a@x.org, b@y.org\r\nSubject: due\r\n\r\ncorpo\n": "", // multi-From: no evaluation
	}
	for msg, want := range cases {
		if got := headerFromDomain([]byte(msg)); got != want {
			t.Errorf("headerFromDomain(%q) = %q, want %q", msg[:min(30, len(msg))], got, want)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var _ = fmt.Sprintf // keep fmt for debug edits
