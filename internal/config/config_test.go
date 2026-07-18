package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// write creates a configuration file, plus one file per entry of
// domains (keyed by file base name, without the .yaml suffix), and
// returns the path of the main configuration.
func write(t *testing.T, yaml string, domains map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	if domains != nil {
		dd := filepath.Join(dir, "domains")
		if err := os.MkdirAll(dd, 0o750); err != nil {
			t.Fatal(err)
		}
		for name, content := range domains {
			if err := os.WriteFile(filepath.Join(dd, name+".yaml"), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	return p
}

const minimal = `
server:
  hostname: mail.example.com
`

// oneDomain is the smallest valid domain file.
var oneDomain = map[string]string{"example.com": "name: example.com\n"}

func TestLoadMinimalDefaults(t *testing.T) {
	cfg, err := Load(write(t, minimal, oneDomain))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Workers != 50 {
		t.Errorf("workers default = %d, want 50", cfg.Server.Workers)
	}
	if cfg.Listeners.SMTP.Address != ":25" || cfg.Listeners.IMAPS.Address != ":993" {
		t.Errorf("listener defaults wrong: %+v", cfg.Listeners)
	}
	if cfg.TLS.CertRoot != "/etc/letsencrypt/live" || cfg.TLS.MinVersion != "1.2" || cfg.TLS.ExpiryWarnDays != 14 {
		t.Errorf("tls defaults wrong: %+v", cfg.TLS)
	}
	if cfg.API.Enabled {
		t.Error("api must be disabled by default")
	}
	if len(cfg.Domains) != 1 || cfg.Domains[0].Name != "example.com" {
		t.Errorf("domains = %+v", cfg.Domains)
	}
}

// The domains directory defaults to a sibling of the config file, so
// a staging or test copy never reaches into /etc.
func TestDomainsDirResolvesBesideConfig(t *testing.T) {
	p := write(t, minimal, oneDomain)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(filepath.Dir(p), "domains")
	if cfg.DomainsDir != want {
		t.Errorf("domains dir = %q, want %q", cfg.DomainsDir, want)
	}
}

func TestDomainsDirExplicit(t *testing.T) {
	dir := t.TempDir()
	elsewhere := filepath.Join(dir, "tenants")
	if err := os.MkdirAll(elsewhere, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(elsewhere, "a.org.yaml"), []byte("name: a.org\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(minimal+"domains_dir: "+filepath.ToSlash(elsewhere)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Domains) != 1 || cfg.Domains[0].Name != "a.org" {
		t.Errorf("domains = %+v", cfg.Domains)
	}
}

// Domains used to live inline. Silently ignoring them would leave an
// operator convinced a domain is hosted when it is not.
func TestInlineDomainsRejectedWithMigrationHint(t *testing.T) {
	y := minimal + "domains:\n  - name: example.com\n"
	_, err := Load(write(t, y, nil))
	if err == nil {
		t.Fatal("inline domains must be rejected")
	}
	if !strings.Contains(err.Error(), "one file per domain") {
		t.Errorf("the error should explain the migration: %v", err)
	}

	y = minimal + "users:\n  - email: a@example.com\n    maildir: /var/mail/a\n"
	if _, err := Load(write(t, y, nil)); err == nil {
		t.Fatal("inline users must be rejected too")
	}
}

func TestDomainFileNameIsTheDomain(t *testing.T) {
	// A file with no name key takes the domain from its file name.
	cfg, err := Load(write(t, minimal, map[string]string{"studenti.ente.it": "users: []\n"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Domains) != 1 || cfg.Domains[0].Name != "studenti.ente.it" {
		t.Fatalf("domains = %+v", cfg.Domains)
	}
}

func TestDomainFileNameMismatchIsReported(t *testing.T) {
	// A name that disagrees with the file name is a typo that would
	// otherwise create a domain nobody meant to host.
	cfg, err := Load(write(t, minimal, map[string]string{"example.com": "name: exemple.com\n"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Domains) != 0 {
		t.Errorf("a mismatched domain must not load: %+v", cfg.Domains)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "exemple.com") {
			found = true
		}
	}
	if !found {
		t.Errorf("want a warning naming the mismatch, got %v", cfg.Warnings)
	}
}

// One broken customer file must not stop the other domains: the
// server keeps running, that domain simply does not exist.
func TestBrokenDomainFileSkippedNotFatal(t *testing.T) {
	cfg, err := Load(write(t, minimal, map[string]string{
		"good.org": "name: good.org\n",
		"bad.org":  "name: bad.org\nusers: [this is not a list of mappings\n",
	}))
	if err != nil {
		t.Fatalf("a broken domain file must not fail the whole load: %v", err)
	}
	if len(cfg.Domains) != 1 || cfg.Domains[0].Name != "good.org" {
		t.Errorf("the healthy domain should still load: %+v", cfg.Domains)
	}
	if len(cfg.Warnings) == 0 {
		t.Error("the broken file must be reported")
	}
}

func TestNonYamlFilesIgnored(t *testing.T) {
	dir := t.TempDir()
	dd := filepath.Join(dir, "domains")
	os.MkdirAll(dd, 0o750)
	for name, content := range map[string]string{
		"good.org.yaml":        "name: good.org\n",
		"old.org.yaml.example": "name: old.org\n",
		"backup.org.yaml.bak":  "name: backup.org\n",
		".hidden.org.yaml":     "name: hidden.org\n",
		"notes.txt":            "not a domain",
	} {
		os.WriteFile(filepath.Join(dd, name), []byte(content), 0o600)
	}
	p := filepath.Join(dir, "config.yaml")
	os.WriteFile(p, []byte(minimal), 0o600)

	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Domains) != 1 || cfg.Domains[0].Name != "good.org" {
		t.Errorf("only .yaml files should load, got %+v", cfg.Domains)
	}
}

func TestUsersCollectedFromDomainFiles(t *testing.T) {
	cfg, err := Load(write(t, minimal, map[string]string{
		"a.org": "name: a.org\nusers:\n  - email: x@a.org\n    maildir: /var/mail/a/x\n",
		"b.org": "name: b.org\nusers:\n  - email: y@b.org\n    maildir: /var/mail/b/y\n",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Users) != 2 {
		t.Fatalf("users = %+v", cfg.Users)
	}
	if _, ok := cfg.PasswordHashFor("x@a.org"); ok {
		t.Error("a user without a hash must not authenticate")
	}
}

func TestHostnameRequired(t *testing.T) {
	if _, err := Load(write(t, "server:\n  workers: 10\n", oneDomain)); err == nil {
		t.Fatal("want error for missing hostname")
	}
}

func TestHostnameNormalized(t *testing.T) {
	cfg, err := Load(write(t, "server:\n  hostname: MAIL.Example.COM.\n",
		map[string]string{"example.com": "name: Example.COM.\n"}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Hostname != "mail.example.com" {
		t.Errorf("hostname = %q", cfg.Server.Hostname)
	}
	if len(cfg.Domains) != 1 || cfg.Domains[0].Name != "example.com" {
		t.Errorf("domain = %+v", cfg.Domains)
	}
}

func TestUnknownFieldRejected(t *testing.T) {
	if _, err := Load(write(t, minimal+"\ntypo_field: 1\n", oneDomain)); err == nil {
		t.Fatal("want error for unknown field")
	}
	// And in a domain file too.
	cfg, err := Load(write(t, minimal, map[string]string{"example.com": "name: example.com\ntypo: 1\n"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Domains) != 0 {
		t.Error("a domain file with an unknown field must not load")
	}
}

func TestDuplicateDomainRejected(t *testing.T) {
	// Two files naming the same domain: the second is ignored with a
	// warning rather than silently shadowing the first.
	dir := t.TempDir()
	dd := filepath.Join(dir, "domains")
	os.MkdirAll(dd, 0o750)
	os.WriteFile(filepath.Join(dd, "example.com.yaml"), []byte("name: example.com\n"), 0o600)
	os.WriteFile(filepath.Join(dd, "EXAMPLE.COM.yaml"), []byte("name: EXAMPLE.COM\n"), 0o600)
	p := filepath.Join(dir, "config.yaml")
	os.WriteFile(p, []byte(minimal), 0o600)

	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Domains) != 1 {
		t.Errorf("a duplicate domain must not load twice: %+v", cfg.Domains)
	}
}

func TestSystemUserDefaults(t *testing.T) {
	cfg, err := Load(write(t, "server:\n  hostname: mail.ostap.dev\n",
		map[string]string{"ostap.dev": "name: ostap.dev\nstorage:\n  type: system_user\n  user: ostap\n"}))
	if err != nil {
		t.Fatal(err)
	}
	st := cfg.Domains[0].Storage
	if st.Home != "/home/ostap" {
		t.Errorf("home = %q", st.Home)
	}
	if got := st.MaildirPath(); got != "/home/ostap/mail" {
		t.Errorf("maildir = %q", got)
	}
}

func TestSystemUserRequiresUser(t *testing.T) {
	_, err := Load(write(t, "server:\n  hostname: m.x.it\n",
		map[string]string{"x.it": "name: x.it\nstorage:\n  type: system_user\n"}))
	if err == nil {
		t.Fatal("want error for system_user without user")
	}
}

func TestAPIEnabledRequiresKeys(t *testing.T) {
	y := minimal + "api:\n  enabled: true\n"
	if _, err := Load(write(t, y, oneDomain)); err == nil {
		t.Fatal("want error: api enabled without keys must not start")
	}
	y = minimal + "api:\n  enabled: true\n  keys: [\"0123456789abcdef0123456789abcdef\"]\n"
	if _, err := Load(write(t, y, oneDomain)); err != nil {
		t.Fatalf("api with key should load: %v", err)
	}
}

func TestBadListenerAddress(t *testing.T) {
	y := "server:\n  hostname: m.x.it\nlisteners:\n  smtp:\n    address: \"nonsense\"\n"
	if _, err := Load(write(t, y, oneDomain)); err == nil {
		t.Fatal("want error for bad listener address")
	}
}

func TestUserDomainWarning(t *testing.T) {
	// A mailbox whose domain is not the file it lives in is almost
	// always a copy-paste mistake.
	cfg, err := Load(write(t, minimal, map[string]string{
		"example.com": "name: example.com\nusers:\n  - email: a@other.org\n    maildir: /var/mail/other.org/a\n",
	}))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "other.org") {
			found = true
		}
	}
	if !found {
		t.Errorf("want warning about unconfigured domain, got %v", cfg.Warnings)
	}
}

func TestNoDomainsWarns(t *testing.T) {
	cfg, err := Load(write(t, minimal, map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "no domain files") {
			found = true
		}
	}
	if !found {
		t.Errorf("an empty domains directory should warn, got %v", cfg.Warnings)
	}
}

func TestPasswordHashFormatValidated(t *testing.T) {
	_, err := Load(write(t, minimal, map[string]string{
		"example.com": "name: example.com\nusers:\n  - email: a@example.com\n    maildir: /var/mail/a\n    password_hash: \"plaintext\"\n",
	}))
	if err == nil {
		t.Fatal("a cleartext password must be refused")
	}
	if !strings.Contains(err.Error(), "argon2id") {
		t.Errorf("the error should name the accepted formats: %v", err)
	}
}

func TestManagerReloadKeepsOldOnError(t *testing.T) {
	p := write(t, minimal, oneDomain)
	m, err := NewManager(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("server: [broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.Reload(); err == nil {
		t.Fatal("want reload error")
	}
	if m.Get().Server.Hostname != "mail.example.com" {
		t.Error("broken reload must keep previous config")
	}
	if m.LastError() == "" {
		t.Error("LastError must report the failed reload")
	}
}

// A domain added on disk appears after a reload, without touching the
// main configuration file.
func TestReloadPicksUpNewDomainFile(t *testing.T) {
	p := write(t, minimal, oneDomain)
	m, err := NewManager(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Get().Domains) != 1 {
		t.Fatalf("domains = %+v", m.Get().Domains)
	}

	dd := filepath.Join(filepath.Dir(p), "domains")
	if err := os.WriteFile(filepath.Join(dd, "nuovo.it.yaml"), []byte("name: nuovo.it\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.Reload(); err != nil {
		t.Fatal(err)
	}
	if len(m.Get().Domains) != 2 {
		t.Errorf("a new domain file should appear after reload: %+v", m.Get().Domains)
	}
	if !m.Get().HasDomain("nuovo.it") {
		t.Error("nuovo.it should be hosted")
	}
}
