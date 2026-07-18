package checks

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ostap-mykhaylyak/kavira/internal/config"
)

// testConfig returns a well-formed configuration to mutate per test.
func testConfig(t *testing.T) (*config.Config, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `
server:
  hostname: mail.example.com
tls:
  cert_root: ` + filepath.ToSlash(filepath.Join(dir, "certs")) + `
queue:
  dir: ` + filepath.ToSlash(filepath.Join(dir, "queue")) + `
dkim:
  dir: ` + filepath.ToSlash(filepath.Join(dir, "dkim")) + `
`
	if err := os.WriteFile(path, []byte(yaml), 0o640); err != nil {
		t.Fatal(err)
	}
	// Domains live in their own directory beside the config file.
	domainsDir := filepath.Join(dir, "domains")
	if err := os.MkdirAll(domainsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	domain := `name: example.com
users:
  - email: admin@example.com
    maildir: ` + filepath.ToSlash(filepath.Join(dir, "mail", "admin")) + `
    password_hash: "$argon2id$v=19$m=65536,t=3,p=4$AAAA$BBBB"
`
	if err := os.WriteFile(filepath.Join(domainsDir, "example.com.yaml"), []byte(domain), 0o640); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	// Recreate the layout with the modes `make install` uses: the
	// audit checks permissions, so testing it against whatever
	// t.TempDir() happens to produce (0755 under a default umask)
	// tests the test framework, not kavira.
	for _, d := range []struct {
		path string
		mode os.FileMode
	}{
		{cfg.Queue.Dir, 0o750},
		{cfg.DKIM.Dir, 0o700},
	} {
		if err := os.MkdirAll(d.path, d.mode); err != nil {
			t.Fatal(err)
		}
		// MkdirAll applies the umask; set the mode explicitly.
		if err := os.Chmod(d.path, d.mode); err != nil {
			t.Fatal(err)
		}
	}
	return cfg, path
}

// find returns the result for a named check.
func find(r *Report, name string) (Result, bool) {
	for _, res := range r.Results {
		if res.Name == name {
			return res, true
		}
	}
	return Result{}, false
}

func TestAuditPassesOnSaneConfig(t *testing.T) {
	cfg, path := testConfig(t)
	r := Audit(cfg, path)

	if _, _, fail, _ := r.Counts(); fail > 0 {
		var failures []string
		for _, res := range r.Results {
			if res.Status == Fail {
				failures = append(failures, res.Name+": "+res.Detail)
			}
		}
		t.Errorf("a sane config should not fail the audit:\n%s", strings.Join(failures, "\n"))
	}
	if r.ExitCode() != 0 {
		t.Errorf("exit code = %d, want 0", r.ExitCode())
	}
	// The structural guarantees must be stated explicitly.
	if res, ok := find(r, "open relay"); !ok || res.Status != Pass {
		t.Errorf("audit should assert the anti-relay guarantee: %+v", res)
	}
	if res, ok := find(r, "VRFY/EXPN"); !ok || res.Status != Pass {
		t.Errorf("audit should assert VRFY/EXPN are disabled: %+v", res)
	}
}

func TestAuditFailsOnDisabledRateLimits(t *testing.T) {
	cfg, path := testConfig(t)
	no := false
	cfg.RateLimit.Inbound.Enabled = &no
	cfg.RateLimit.Outbound.Enabled = &no

	r := Audit(cfg, path)
	in, _ := find(r, "inbound rate limit")
	out, _ := find(r, "outbound rate limit")
	if in.Status != Fail {
		t.Errorf("disabled inbound rate limiting must fail the audit: %+v", in)
	}
	if out.Status != Fail {
		t.Errorf("disabled outbound rate limiting must fail the audit: %+v", out)
	}
	if r.ExitCode() != 1 {
		t.Errorf("exit code = %d, want 1", r.ExitCode())
	}
}

func TestAuditFlagsContainerHostname(t *testing.T) {
	cfg, path := testConfig(t)
	cfg.Server.Hostname = "container01.lxd"

	r := Audit(cfg, path)
	res, ok := find(r, "public hostname")
	if !ok || res.Status != Fail {
		t.Fatalf("a .lxd hostname must fail: %+v", res)
	}
	if res.Fix == "" {
		t.Error("a failure must come with a remedy")
	}
}

func TestAuditReportsUsersWithoutPassword(t *testing.T) {
	cfg, path := testConfig(t)
	cfg.Users = append(cfg.Users, config.User{
		Email: "info@example.com", Type: "virtual", Maildir: "/var/mail/info",
	})

	r := Audit(cfg, path)
	res, ok := find(r, "mailbox passwords")
	if !ok || res.Status != Warn {
		t.Fatalf("a user without a password should warn: %+v", res)
	}
	if !strings.Contains(res.Detail, "1 of 2") {
		t.Errorf("detail should count the users: %q", res.Detail)
	}
}

func TestAuditFlagsWidePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions are not meaningful on this platform")
	}
	cfg, path := testConfig(t)

	// A world-readable queue exposes everyone's mail in transit.
	if err := os.Chmod(cfg.Queue.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	r := Audit(cfg, path)
	res, ok := find(r, "queue directory")
	if !ok || res.Status != Fail {
		t.Fatalf("a 0755 queue directory must fail: %+v", res)
	}
	if !strings.Contains(res.Fix, "chmod") {
		t.Errorf("the remedy should be actionable: %q", res.Fix)
	}

	// A DKIM private key readable beyond its owner lets anyone sign
	// as the domain: the one secret whose leak is unrecoverable.
	keyDir := filepath.Join(cfg.DKIM.Dir, "example.com")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(keyDir, "default.pem")
	if err := os.WriteFile(keyPath, []byte("-----BEGIN PRIVATE KEY-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r = Audit(cfg, path)
	res, ok = find(r, "dkim keys")
	if !ok || res.Status != Fail {
		t.Fatalf("a 0644 DKIM key must fail: %+v", res)
	}

	// And the same layout with correct modes must pass.
	if err := os.Chmod(cfg.Queue.Dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	r = Audit(cfg, path)
	if res, _ := find(r, "queue directory"); res.Status != Pass {
		t.Errorf("a 0750 queue directory should pass: %+v", res)
	}
	if res, _ := find(r, "dkim keys"); res.Status != Pass {
		t.Errorf("a 0600 DKIM key should pass: %+v", res)
	}
}

func TestAuditFlagsWeakAPIKeys(t *testing.T) {
	cfg, path := testConfig(t)
	cfg.API.Enabled = true
	cfg.API.Keys = []string{"short"}

	r := Audit(cfg, path)
	res, ok := find(r, "api keys")
	if !ok || res.Status != Warn {
		t.Fatalf("a short API key should warn: %+v", res)
	}
}

func TestContainerCheckWithoutContainer(t *testing.T) {
	cfg, _ := testConfig(t)
	r := ContainerCheck(cfg)

	if res, ok := find(r, "SMTP banner"); !ok || !strings.Contains(res.Detail, "mail.example.com") {
		t.Errorf("banner check should show the public name: %+v", res)
	}
	// Container mode off and no runtime: the trace-header check is
	// not applicable rather than failing.
	if res, ok := find(r, "trace headers"); !ok || res.Status != Skip {
		t.Errorf("trace headers should be skipped without container mode: %+v", res)
	}
}

func TestContainerCheckMasksInternalAddress(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.Container.Enabled = true
	cfg.Container.PublicIP = "203.0.113.10"
	cfg.Container.InternalIP = "10.1.0.20"

	r := ContainerCheck(cfg)
	res, ok := find(r, "trace headers")
	if !ok || res.Status != Pass {
		t.Fatalf("masking should pass: %+v", res)
	}
	if !strings.Contains(res.Detail, "10.1.0.20") || !strings.Contains(res.Detail, "203.0.113.10") {
		t.Errorf("the detail should show the substitution: %q", res.Detail)
	}
	// Inbound traceability must survive.
	if res, ok := find(r, "inbound source addresses"); !ok || res.Status != Pass {
		t.Errorf("public sources must be preserved: %+v", res)
	}
}

func TestContainerCheckAlwaysMentionsBackups(t *testing.T) {
	cfg, _ := testConfig(t)
	r := ContainerCheck(cfg)
	res, ok := find(r, "backups")
	if !ok || res.Status != Warn {
		t.Fatalf("the operator must be told kavira takes no backups: %+v", res)
	}
	if !strings.Contains(res.Fix, "snapshot") {
		t.Errorf("the remedy should point at snapshots: %q", res.Fix)
	}
}

func TestReportPrintAndExit(t *testing.T) {
	r := &Report{}
	r.Pass("Section", "ok check", "fine")
	r.Warn("Section", "iffy check", "not ideal", "do this")
	if r.ExitCode() != 0 {
		t.Error("warnings alone must not fail the run")
	}
	r.Fail("Section", "broken check", "very wrong", "fix this")
	if r.ExitCode() != 1 {
		t.Error("a failure must set the exit code")
	}

	var sb strings.Builder
	r.Print(&sb, "test report")
	out := sb.String()
	for _, want := range []string{"test report", "[PASS] ok check", "[WARN] iffy check", "[FAIL] broken check", "fix: fix this", "1 passed, 1 warnings, 1 failures"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	// A passing check must not print a remedy.
	if strings.Contains(out, "fix: \n") {
		t.Error("empty remedies must not be printed")
	}
}

func TestDKIMKeyComparison(t *testing.T) {
	const key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtest"
	a := "v=DKIM1; k=rsa; p=" + key
	// DNS may split and pad the value; that is cosmetic.
	b := "v=DKIM1; k=rsa; p=" + key[:20] + " " + key[20:]
	if !sameDKIMKey(a, b) {
		t.Error("whitespace inside the key must not count as a difference")
	}
	if sameDKIMKey(a, "v=DKIM1; k=rsa; p=DIFFERENTKEY") {
		t.Error("different keys must not compare equal")
	}
	if sameDKIMKey("v=DKIM1; k=rsa", "v=DKIM1; k=rsa") {
		t.Error("records without a p= tag must not compare equal")
	}
}
