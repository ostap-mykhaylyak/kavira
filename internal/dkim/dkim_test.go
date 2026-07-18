package dkim

import (
	"bytes"
	"strings"
	"testing"

	msgdkim "github.com/emersion/go-msgauth/dkim"
)

const sampleMsg = "From: admin@example.com\r\n" +
	"To: friend@remote.org\r\n" +
	"Subject: firmata\r\n" +
	"\r\n" +
	"corpo del messaggio\r\n"

func TestGenerateSignVerifyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	name, value, err := Generate(dir, "example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if name != "default._domainkey.example.com" {
		t.Errorf("txt name = %q", name)
	}
	if !strings.HasPrefix(value, "v=DKIM1; k=rsa; p=") {
		t.Errorf("txt value = %q", value)
	}

	store := NewStore(dir)
	signer, ok := store.Signer("example.com", "")
	if !ok {
		t.Fatal("key not loadable after generation")
	}

	signed, err := Sign([]byte(sampleMsg), "example.com", "", signer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(signed, []byte("DKIM-Signature:")) {
		t.Fatalf("missing signature header:\n%s", signed)
	}

	// Verify against the freshly published record (stubbed DNS).
	verifs, err := msgdkim.VerifyWithOptions(bytes.NewReader(signed), &msgdkim.VerifyOptions{
		LookupTXT: func(domain string) ([]string, error) {
			if domain == name {
				return []string{value}, nil
			}
			return nil, nil
		},
	})
	if err != nil || len(verifs) != 1 {
		t.Fatalf("verify: %v (%d results)", err, len(verifs))
	}
	if verifs[0].Err != nil {
		t.Errorf("signature invalid: %v", verifs[0].Err)
	}
	if verifs[0].Domain != "example.com" {
		t.Errorf("signed domain = %q", verifs[0].Domain)
	}
}

func TestGenerateRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := Generate(dir, "example.com", ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Generate(dir, "example.com", ""); err == nil {
		t.Fatal("second Generate must refuse to overwrite")
	}
	// But the existing record can be re-displayed.
	if _, _, err := NewStore(dir).TXTRecord("example.com", ""); err != nil {
		t.Errorf("TXTRecord on existing key: %v", err)
	}
}

func TestSignerMissingKey(t *testing.T) {
	if _, ok := NewStore(t.TempDir()).Signer("nokey.org", ""); ok {
		t.Fatal("missing key must report ok=false")
	}
}
