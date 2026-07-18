// Package blacklist queries DNS blacklists: DNSBL for connecting IPs
// and URIBL for hostnames found in message bodies.
//
// Results are cached for a while: a spam run hits the same few
// sources repeatedly, and a DNS lookup per message per list would
// both slow delivery and hammer the list operators, who rate-limit
// (and eventually block) heavy queriers.
package blacklist

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

// Default public lists. Operators with heavy volume should register
// with the providers and use their own mirrors instead.
var (
	DefaultDNSBL = []string{
		"zen.spamhaus.org",
		"b.barracudacentral.org",
		"dnsbl.sorbs.net",
		"dnsbl-1.uceprotect.net",
	}
	DefaultURIBL = []string{
		"dbl.spamhaus.org",
		"multi.uribl.com",
	}
)

type entry struct {
	listed  bool
	on      []string
	expires time.Time
}

// Checker queries blacklists with a small cache.
type Checker struct {
	// DNSBL and URIBL are the zones to query. Empty disables that
	// kind of lookup.
	DNSBL []string
	URIBL []string
	// TTL is how long an answer is cached.
	TTL time.Duration
	// Timeout bounds a single lookup.
	Timeout time.Duration
	// Resolver overrides DNS (tests).
	Resolver interface {
		LookupHost(ctx context.Context, host string) ([]string, error)
	}

	mu    sync.Mutex
	cache map[string]entry
}

// New builds a Checker with sensible defaults.
func New(dnsbl, uribl []string, ttl time.Duration) *Checker {
	if ttl == 0 {
		ttl = time.Hour
	}
	return &Checker{
		DNSBL:   dnsbl,
		URIBL:   uribl,
		TTL:     ttl,
		Timeout: 3 * time.Second,
		cache:   map[string]entry{},
	}
}

func (c *Checker) resolver() interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
} {
	if c.Resolver != nil {
		return c.Resolver
	}
	return net.DefaultResolver
}

// cached returns a live cache entry.
func (c *Checker) cached(key string) (entry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.cache[key]
	if !ok || time.Now().After(e.expires) {
		return entry{}, false
	}
	return e, true
}

func (c *Checker) store(key string, e entry) {
	e.expires = time.Now().Add(c.TTL)
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.cache) > 65536 {
		// Cheap bound: drop everything rather than track an LRU for
		// what is only an optimization.
		c.cache = map[string]entry{}
	}
	c.cache[key] = e
}

// reverseIP renders an IP in the reversed form DNSBLs expect. IPv6 is
// nibble-reversed per RFC 5782.
func reverseIP(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return strings.Join([]string{
			itoa(v4[3]), itoa(v4[2]), itoa(v4[1]), itoa(v4[0]),
		}, ".")
	}
	v6 := ip.To16()
	if v6 == nil {
		return ""
	}
	const hex = "0123456789abcdef"
	parts := make([]string, 0, 32)
	for i := len(v6) - 1; i >= 0; i-- {
		parts = append(parts, string(hex[v6[i]&0xf]), string(hex[v6[i]>>4]))
	}
	return strings.Join(parts, ".")
}

func itoa(b byte) string {
	if b == 0 {
		return "0"
	}
	var buf [3]byte
	i := len(buf)
	for b > 0 {
		i--
		buf[i] = '0' + b%10
		b /= 10
	}
	return string(buf[i:])
}

// ListedIP reports whether an IP appears on any configured DNSBL, and
// which ones.
func (c *Checker) ListedIP(ipStr string) (bool, []string) {
	if len(c.DNSBL) == 0 {
		return false, nil
	}
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() {
		// Private and loopback space is never on a public list;
		// querying it leaks internal topology to the list operator.
		return false, nil
	}
	key := "ip:" + ipStr
	if e, ok := c.cached(key); ok {
		return e.listed, e.on
	}
	rev := reverseIP(ip)
	if rev == "" {
		return false, nil
	}
	var on []string
	for _, zone := range c.DNSBL {
		if c.lookup(rev + "." + zone) {
			on = append(on, zone)
		}
	}
	e := entry{listed: len(on) > 0, on: on}
	c.store(key, e)
	return e.listed, e.on
}

// ListedDomain reports whether a hostname appears on any URIBL.
func (c *Checker) ListedDomain(domain string) bool {
	if len(c.URIBL) == 0 || domain == "" {
		return false
	}
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if net.ParseIP(domain) != nil {
		return false // IP literals are handled by the DNSBL path
	}
	key := "dom:" + domain
	if e, ok := c.cached(key); ok {
		return e.listed
	}
	var on []string
	for _, zone := range c.URIBL {
		if c.lookup(domain + "." + zone) {
			on = append(on, zone)
		}
	}
	e := entry{listed: len(on) > 0, on: on}
	c.store(key, e)
	return e.listed
}

// lookup performs one blacklist query: any A record means listed.
func (c *Checker) lookup(name string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
	defer cancel()
	addrs, err := c.resolver().LookupHost(ctx, name)
	if err != nil {
		return false // NXDOMAIN (not listed) or a resolver problem
	}
	for _, a := range addrs {
		// Listings answer in 127.0.0.0/8; anything else (notably a
		// wildcard-hijacking resolver) is not a real listing.
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil && ip.To4()[0] == 127 {
			return true
		}
	}
	return false
}
