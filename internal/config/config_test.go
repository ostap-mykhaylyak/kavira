package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, yaml string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const minimal = `
server:
  hostname: mail.example.com
domains:
  - name: example.com
`

func TestLoadMinimalDefaults(t *testing.T) {
	cfg, err := Load(write(t, minimal))
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
}

func TestHostnameRequired(t *testing.T) {
	if _, err := Load(write(t, `domains: [{name: example.com}]`)); err == nil {
		t.Fatal("want error for missing hostname")
	}
}

func TestHostnameNormalized(t *testing.T) {
	cfg, err := Load(write(t, "server:\n  hostname: MAIL.Example.COM.\ndomains:\n  - name: Example.COM.\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Hostname != "mail.example.com" {
		t.Errorf("hostname = %q", cfg.Server.Hostname)
	}
	if cfg.Domains[0].Name != "example.com" {
		t.Errorf("domain = %q", cfg.Domains[0].Name)
	}
}

func TestUnknownFieldRejected(t *testing.T) {
	if _, err := Load(write(t, minimal+"\ntypo_field: 1\n")); err == nil {
		t.Fatal("want error for unknown field")
	}
}

func TestDuplicateDomainRejected(t *testing.T) {
	y := "server:\n  hostname: mail.example.com\ndomains:\n  - name: example.com\n  - name: EXAMPLE.com\n"
	if _, err := Load(write(t, y)); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("want duplicate-domain error, got %v", err)
	}
}

func TestSystemUserDefaults(t *testing.T) {
	y := `
server:
  hostname: mail.ostap.dev
domains:
  - name: ostap.dev
    storage:
      type: system_user
      user: ostap
`
	cfg, err := Load(write(t, y))
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
	y := "server:\n  hostname: m.x.it\ndomains:\n  - name: x.it\n    storage:\n      type: system_user\n"
	if _, err := Load(write(t, y)); err == nil {
		t.Fatal("want error for system_user without user")
	}
}

func TestAPIEnabledRequiresKeys(t *testing.T) {
	y := minimal + "api:\n  enabled: true\n"
	if _, err := Load(write(t, y)); err == nil {
		t.Fatal("want error: api enabled without keys must not start")
	}
	y = minimal + "api:\n  enabled: true\n  keys: [\"0123456789abcdef0123456789abcdef\"]\n"
	if _, err := Load(write(t, y)); err != nil {
		t.Fatalf("api with key should load: %v", err)
	}
}

func TestBadListenerAddress(t *testing.T) {
	y := "server:\n  hostname: m.x.it\nlisteners:\n  smtp:\n    address: \"nonsense\"\ndomains:\n  - name: x.it\n"
	if _, err := Load(write(t, y)); err == nil {
		t.Fatal("want error for bad listener address")
	}
}

func TestUserDomainWarning(t *testing.T) {
	y := minimal + "users:\n  - email: a@other.org\n    maildir: /var/mail/other.org/a\n"
	cfg, err := Load(write(t, y))
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

func TestManagerReloadKeepsOldOnError(t *testing.T) {
	p := write(t, minimal)
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
