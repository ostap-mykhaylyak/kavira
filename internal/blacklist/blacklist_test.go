package blacklist

import (
	"context"
	"net"
	"testing"
	"time"
)

// stubResolver answers from a fixed map and counts lookups.
type stubResolver struct {
	listed map[string]string // query name -> answer
	calls  int
}

func (s *stubResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	s.calls++
	if a, ok := s.listed[host]; ok {
		return []string{a}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func TestReverseIPv4(t *testing.T) {
	if got := reverseIP(net.ParseIP("203.0.113.10")); got != "10.113.0.203" {
		t.Errorf("reverseIP = %q", got)
	}
	if got := reverseIP(net.ParseIP("1.2.3.4")); got != "4.3.2.1" {
		t.Errorf("reverseIP = %q", got)
	}
}

func TestListedIP(t *testing.T) {
	r := &stubResolver{listed: map[string]string{
		"10.113.0.203.zen.spamhaus.org": "127.0.0.2",
	}}
	c := New([]string{"zen.spamhaus.org", "dnsbl.sorbs.net"}, nil, time.Hour)
	c.Resolver = r

	listed, zones := c.ListedIP("203.0.113.10")
	if !listed || len(zones) != 1 || zones[0] != "zen.spamhaus.org" {
		t.Fatalf("listed=%v zones=%v", listed, zones)
	}
	if listed, _ := c.ListedIP("198.51.100.7"); listed {
		t.Error("an unlisted IP must not be reported")
	}
}

func TestNonLoopbackAnswerIgnored(t *testing.T) {
	// A hijacking resolver that answers everything with a public IP
	// must not turn every sender into a blacklisted one.
	r := &stubResolver{listed: map[string]string{
		"10.113.0.203.zen.spamhaus.org": "93.184.216.34",
	}}
	c := New([]string{"zen.spamhaus.org"}, nil, time.Hour)
	c.Resolver = r
	if listed, _ := c.ListedIP("203.0.113.10"); listed {
		t.Error("only 127.0.0.0/8 answers count as a listing")
	}
}

func TestPrivateAndLoopbackSkipped(t *testing.T) {
	r := &stubResolver{listed: map[string]string{}}
	c := New([]string{"zen.spamhaus.org"}, nil, time.Hour)
	c.Resolver = r

	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "192.168.1.5", "172.16.0.1"} {
		if listed, _ := c.ListedIP(ip); listed {
			t.Errorf("%s must not be reported as listed", ip)
		}
	}
	if r.calls != 0 {
		t.Errorf("private space must not be queried at all (leaks topology): %d calls", r.calls)
	}
}

func TestResultsCached(t *testing.T) {
	r := &stubResolver{listed: map[string]string{
		"10.113.0.203.zen.spamhaus.org": "127.0.0.2",
	}}
	c := New([]string{"zen.spamhaus.org"}, nil, time.Hour)
	c.Resolver = r

	c.ListedIP("203.0.113.10")
	first := r.calls
	for i := 0; i < 5; i++ {
		c.ListedIP("203.0.113.10")
	}
	if r.calls != first {
		t.Errorf("repeat lookups must be served from cache: %d -> %d calls", first, r.calls)
	}
}

func TestListedDomain(t *testing.T) {
	r := &stubResolver{listed: map[string]string{
		"cattivo.tld.dbl.spamhaus.org": "127.0.1.2",
	}}
	c := New(nil, []string{"dbl.spamhaus.org"}, time.Hour)
	c.Resolver = r

	if !c.ListedDomain("cattivo.tld") {
		t.Error("listed domain not detected")
	}
	if !c.ListedDomain("CATTIVO.TLD.") {
		t.Error("domain matching must be case- and dot-insensitive")
	}
	if c.ListedDomain("buono.tld") {
		t.Error("unlisted domain reported")
	}
	// An IP literal is the DNSBL's job, not the URIBL's.
	if c.ListedDomain("203.0.113.10") {
		t.Error("IP literals must not be queried against a URIBL")
	}
}

func TestDisabledWhenNoZones(t *testing.T) {
	r := &stubResolver{listed: map[string]string{}}
	c := New(nil, nil, time.Hour)
	c.Resolver = r
	if listed, _ := c.ListedIP("203.0.113.10"); listed {
		t.Error("no zones configured means no listings")
	}
	if c.ListedDomain("x.tld") {
		t.Error("no zones configured means no listings")
	}
	if r.calls != 0 {
		t.Errorf("no zones must mean no lookups: %d", r.calls)
	}
}
