// Package tls owns certificate loading and SNI selection for kavira.
//
// Certificates are always wildcards issued on the configured (base)
// domain, living in the standard Let's Encrypt layout:
//
//	<cert_root>/<domain>/fullchain.pem
//	<cert_root>/<domain>/privkey.pem
//
// There is never a per-subdomain directory: mail.example.com is served
// by the certificate of the configured domain example.com (wildcard
// *.example.com), and prova@studenti.ente.it by the certificate of the
// configured domain studenti.ente.it. The SNI name is resolved to the
// longest configured domain suffix, so a more specific configured
// domain always wins over a shorter one.
//
// A missing or broken certificate is a warning, not a fatal error: the
// daemon must keep serving the domains whose certificates do load, and
// a fresh install has no certificates yet at all.
package tls

import (
	stdtls "crypto/tls"
	"crypto/x509"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// entry is one loaded certificate.
type entry struct {
	cert     *stdtls.Certificate
	notAfter time.Time
}

// Params is everything the store needs from the configuration.
type Params struct {
	// CertRoot is the Let's Encrypt live directory.
	CertRoot string
	// Hostname selects the default certificate when the client sends
	// no SNI at all.
	Hostname string
	// Domains are the configured domain names.
	Domains []string
	// MinVersion is "1.2" or "1.3".
	MinVersion string
	// ExpiryWarnDays triggers expiry warnings this many days early.
	ExpiryWarnDays int
}

// Store loads certificates and answers SNI lookups. Reload swaps the
// whole state atomically, so it is safe to call while handshakes are
// in flight.
type Store struct {
	mu      sync.RWMutex
	p       Params
	minVer  uint16
	domains []string          // sorted longest-first for suffix match
	certs   map[string]*entry // domain -> certificate
}

// New builds a Store and performs the initial load. Per-domain load
// failures come back as warnings.
func New(p Params) (*Store, []string) {
	s := &Store{}
	warns := s.Reload(p)
	return s, warns
}

// Reload re-reads every certificate according to p and atomically
// replaces the current state. It returns per-domain warnings (missing
// or unreadable certificates, imminent expiries).
func (s *Store) Reload(p Params) []string {
	var warns []string

	minVer := uint16(stdtls.VersionTLS12)
	if p.MinVersion == "1.3" {
		minVer = stdtls.VersionTLS13
	}

	domains := make([]string, len(p.Domains))
	copy(domains, p.Domains)
	// Longest name first: with both ente.it and studenti.ente.it
	// configured, mail.studenti.ente.it must match the longer one.
	sort.Slice(domains, func(i, j int) bool { return len(domains[i]) > len(domains[j]) })

	certs := make(map[string]*entry, len(domains))
	for _, d := range domains {
		e, err := loadCert(p.CertRoot, d)
		if err != nil {
			warns = append(warns, fmt.Sprintf("domain %s: %v", d, err))
			continue
		}
		certs[d] = e
	}

	s.mu.Lock()
	s.p = p
	s.minVer = minVer
	s.domains = domains
	s.certs = certs
	s.mu.Unlock()

	warns = append(warns, s.ExpiryWarnings(time.Now())...)
	return warns
}

// loadCert reads the Let's Encrypt pair for one configured domain.
func loadCert(root, domain string) (*entry, error) {
	dir := filepath.Join(root, domain)
	cert, err := stdtls.LoadX509KeyPair(
		filepath.Join(dir, "fullchain.pem"),
		filepath.Join(dir, "privkey.pem"),
	)
	if err != nil {
		return nil, fmt.Errorf("certificate load failed: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("certificate parse failed: %w", err)
	}
	cert.Leaf = leaf
	return &entry{cert: &cert, notAfter: leaf.NotAfter}, nil
}

// Match resolves an SNI name to the configured domain that serves it,
// or "" when nothing matches. The longest configured suffix wins.
func (s *Store) Match(sni string) string {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(sni)), ".")
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.matchLocked(name)
}

func (s *Store) matchLocked(name string) string {
	if name == "" {
		return ""
	}
	for _, d := range s.domains {
		if name == d || strings.HasSuffix(name, "."+d) {
			return d
		}
	}
	return ""
}

// GetCertificate implements crypto/tls.Config.GetCertificate. Clients
// without SNI get the certificate of the configured server hostname.
func (s *Store) GetCertificate(chi *stdtls.ClientHelloInfo) (*stdtls.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	name := strings.TrimSuffix(strings.ToLower(chi.ServerName), ".")
	d := s.matchLocked(name)
	if d == "" {
		d = s.matchLocked(s.p.Hostname)
	}
	if e := s.certs[d]; e != nil {
		return e.cert, nil
	}
	return nil, fmt.Errorf("no certificate for %q", chi.ServerName)
}

// Config returns a crypto/tls server configuration wired to the store.
// TLS 1.0/1.1 and SSLv3 are never offered: the floor is 1.2.
func (s *Store) Config() *stdtls.Config {
	s.mu.RLock()
	minVer := s.minVer
	s.mu.RUnlock()
	return &stdtls.Config{
		MinVersion:     minVer,
		GetCertificate: s.GetCertificate,
	}
}

// Loaded returns the domains whose certificate is currently loaded.
func (s *Store) Loaded() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.certs))
	for d := range s.certs {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// ExpiryWarnings lists loaded certificates expiring within the
// configured window, or already expired, as human-readable warnings.
func (s *Store) ExpiryWarnings(now time.Time) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var warns []string
	limit := now.Add(time.Duration(s.p.ExpiryWarnDays) * 24 * time.Hour)
	for _, d := range s.domains {
		e := s.certs[d]
		if e == nil {
			continue
		}
		switch {
		case e.notAfter.Before(now):
			warns = append(warns, fmt.Sprintf("domain %s: certificate EXPIRED on %s",
				d, e.notAfter.Format(time.DateOnly)))
		case e.notAfter.Before(limit):
			warns = append(warns, fmt.Sprintf("domain %s: certificate expires in %d days (%s)",
				d, int(e.notAfter.Sub(now).Hours()/24), e.notAfter.Format(time.DateOnly)))
		}
	}
	return warns
}
