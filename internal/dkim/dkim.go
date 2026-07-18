// Package dkim manages DKIM keys and signs outbound mail (RFC 6376).
//
// Keys live under the state directory, one per domain and selector:
//
//	/var/lib/kavira/dkim/<domain>/<selector>.pem   (RSA 2048, 0600)
//
// Generate creates the key and returns the DNS TXT record to publish;
// Sign adds the DKIM-Signature header when a key exists for the
// sender domain, and is a no-op otherwise: a domain without a key
// simply sends unsigned mail.
package dkim

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	msgdkim "github.com/emersion/go-msgauth/dkim"
)

// DefaultSelector is used when a domain does not configure one.
const DefaultSelector = "default"

// signedHeaders are the header fields covered by our signatures
// (RFC 6376 section 5.4.1 recommendations). Received is deliberately
// excluded: downstream relays append their own.
var signedHeaders = []string{
	"From", "To", "Cc", "Subject", "Date", "Message-ID",
	"Reply-To", "MIME-Version", "Content-Type", "Content-Transfer-Encoding",
}

// Store loads private keys from the key directory.
type Store struct {
	dir string
}

// NewStore returns a Store rooted at dir.
func NewStore(dir string) *Store { return &Store{dir: dir} }

func (s *Store) keyPath(domain, selector string) string {
	return filepath.Join(s.dir, domain, selector+".pem")
}

// Signer loads the private key for domain/selector. ok is false when
// the domain has no key (unsigned sending is not an error).
func (s *Store) Signer(domain, selector string) (crypto.Signer, bool) {
	if selector == "" {
		selector = DefaultSelector
	}
	b, err := os.ReadFile(s.keyPath(domain, selector))
	if err != nil {
		return nil, false
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, false
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, false
	}
	signer, ok := key.(crypto.Signer)
	return signer, ok
}

// Sign returns msg with a DKIM-Signature header prepended, signed by
// key for domain/selector. Canonicalization is relaxed/relaxed: the
// signature survives ordinary MTA whitespace rewriting.
func Sign(msg []byte, domain, selector string, key crypto.Signer) ([]byte, error) {
	if selector == "" {
		selector = DefaultSelector
	}
	var out bytes.Buffer
	err := msgdkim.Sign(&out, bytes.NewReader(msg), &msgdkim.SignOptions{
		Domain:                 domain,
		Selector:               selector,
		Signer:                 key,
		HeaderCanonicalization: msgdkim.CanonicalizationRelaxed,
		BodyCanonicalization:   msgdkim.CanonicalizationRelaxed,
		HeaderKeys:             signedHeaders,
	})
	if err != nil {
		return nil, fmt.Errorf("dkim sign %s: %w", domain, err)
	}
	return out.Bytes(), nil
}

// Generate creates an RSA 2048 key for domain/selector under dir and
// returns the DNS TXT record to publish. It refuses to overwrite an
// existing key.
func Generate(dir, domain, selector string) (txtName, txtValue string, err error) {
	if selector == "" {
		selector = DefaultSelector
	}
	s := NewStore(dir)
	path := s.keyPath(domain, selector)
	if _, err := os.Stat(path); err == nil {
		return "", "", fmt.Errorf("key already exists: %s (remove it to regenerate)", path)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", "", err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return "", "", err
	}

	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", err
	}
	txtName = fmt.Sprintf("%s._domainkey.%s", selector, domain)
	txtValue = fmt.Sprintf("v=DKIM1; k=rsa; p=%s", base64.StdEncoding.EncodeToString(pub))
	return txtName, txtValue, nil
}

// TXTRecord recomputes the public TXT record of an existing key, for
// re-display.
func (s *Store) TXTRecord(domain, selector string) (txtName, txtValue string, err error) {
	if selector == "" {
		selector = DefaultSelector
	}
	signer, ok := s.Signer(domain, selector)
	if !ok {
		return "", "", fmt.Errorf("no key for %s (selector %s)", domain, selector)
	}
	pub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return "", "", err
	}
	txtName = fmt.Sprintf("%s._domainkey.%s", selector, domain)
	txtValue = fmt.Sprintf("v=DKIM1; k=rsa; p=%s", base64.StdEncoding.EncodeToString(pub))
	return txtName, txtValue, nil
}
