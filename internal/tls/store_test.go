package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// makeCert writes a self-signed wildcard pair for domain under root,
// in the Let's Encrypt layout, expiring at notAfter.
func makeCert(t *testing.T, root, domain string, notAfter time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain, "*." + domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, domain)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, "fullchain.pem"), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	if err := os.WriteFile(filepath.Join(dir, "privkey.pem"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

func params(root string, domains ...string) Params {
	return Params{
		CertRoot:       root,
		Hostname:       "mail." + domains[0],
		Domains:        domains,
		MinVersion:     "1.2",
		ExpiryWarnDays: 14,
	}
}

func TestMatchLongestSuffix(t *testing.T) {
	root := t.TempDir()
	far := time.Now().Add(90 * 24 * time.Hour)
	makeCert(t, root, "ente.it", far)
	makeCert(t, root, "studenti.ente.it", far)

	s, warns := New(params(root, "ente.it", "studenti.ente.it"))
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}

	cases := map[string]string{
		"mail.ente.it":           "ente.it",
		"ente.it":                "ente.it",
		"mail.studenti.ente.it":  "studenti.ente.it",
		"studenti.ente.it":       "studenti.ente.it",
		"imap.studenti.ente.it.": "studenti.ente.it", // trailing dot
		"MAIL.ENTE.IT":           "ente.it",          // case
		"unrelated.example.org":  "",
		"badente.it":             "", // suffix match only on label boundary
	}

	for sni, want := range cases {
		if got := s.Match(sni); got != want {
			t.Errorf("Match(%q) = %q, want %q", sni, got, want)
		}
	}
}

func TestGetCertificateSNIAndDefault(t *testing.T) {
	root := t.TempDir()
	far := time.Now().Add(90 * 24 * time.Hour)
	makeCert(t, root, "example.com", far)
	makeCert(t, root, "ostap.dev", far)

	p := params(root, "example.com", "ostap.dev")
	p.Hostname = "mail.ostap.dev"
	s, warns := New(p)
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}

	got, err := s.GetCertificate(&stdtls.ClientHelloInfo{ServerName: "mail.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if cn := got.Leaf.Subject.CommonName; cn != "example.com" {
		t.Errorf("SNI mail.example.com got cert %q", cn)
	}

	// No SNI: fall back to the server hostname's domain.
	got, err = s.GetCertificate(&stdtls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if cn := got.Leaf.Subject.CommonName; cn != "ostap.dev" {
		t.Errorf("no-SNI default got cert %q", cn)
	}
}

func TestMissingCertIsWarningNotFatal(t *testing.T) {
	root := t.TempDir()
	makeCert(t, root, "example.com", time.Now().Add(90*24*time.Hour))

	s, warns := New(params(root, "example.com", "nocert.org"))
	if len(warns) != 1 {
		t.Fatalf("want 1 warning, got %v", warns)
	}
	if got := s.Loaded(); len(got) != 1 || got[0] != "example.com" {
		t.Errorf("Loaded() = %v", got)
	}
	if _, err := s.GetCertificate(&stdtls.ClientHelloInfo{ServerName: "mail.nocert.org"}); err == nil {
		t.Error("want handshake error for domain without certificate")
	}
}

func TestExpiryWarnings(t *testing.T) {
	root := t.TempDir()
	makeCert(t, root, "soon.dev", time.Now().Add(5*24*time.Hour))

	_, warns := New(params(root, "soon.dev"))
	if len(warns) != 1 {
		t.Fatalf("want expiry warning, got %v", warns)
	}
}

func TestReloadPicksUpNewCert(t *testing.T) {
	root := t.TempDir()
	p := params(root, "example.com")

	s, warns := New(p)
	if len(warns) != 1 {
		t.Fatalf("want missing-cert warning, got %v", warns)
	}

	makeCert(t, root, "example.com", time.Now().Add(90*24*time.Hour))
	if warns := s.Reload(p); len(warns) != 0 {
		t.Fatalf("unexpected warnings after reload: %v", warns)
	}
	if _, err := s.GetCertificate(&stdtls.ClientHelloInfo{ServerName: "mail.example.com"}); err != nil {
		t.Errorf("cert should be served after reload: %v", err)
	}
}

func TestConfigFloor(t *testing.T) {
	root := t.TempDir()
	makeCert(t, root, "example.com", time.Now().Add(90*24*time.Hour))

	s, _ := New(params(root, "example.com"))
	if got := s.Config().MinVersion; got != stdtls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want TLS1.2", got)
	}

	p := params(root, "example.com")
	p.MinVersion = "1.3"
	s.Reload(p)
	if got := s.Config().MinVersion; got != stdtls.VersionTLS13 {
		t.Errorf("MinVersion = %x, want TLS1.3", got)
	}
}
