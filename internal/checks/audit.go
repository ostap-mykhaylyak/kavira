package checks

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ostap-mykhaylyak/kavira/internal/config"
	"github.com/ostap-mykhaylyak/kavira/internal/container"
)

// Audit inspects the local configuration and filesystem. It performs
// no network activity, so it is safe on a machine that is not yet
// serving mail.
func Audit(cfg *config.Config, cfgPath string) *Report {
	r := &Report{}
	auditConfigPosture(r, cfg)
	auditCredentials(r, cfg)
	auditPermissions(r, cfg, cfgPath)
	auditIdentity(r, cfg)
	return r
}

func auditConfigPosture(r *Report, cfg *config.Config) {
	const s = "Configuration"

	for _, w := range cfg.Warnings {
		r.Warn(s, "config warning", w, "review the configuration")
	}

	// Anti open relay is structural in kavira, not a setting: state
	// it explicitly so an auditor sees it was considered.
	r.Pass(s, "open relay", "port 25 accepts local recipients only; relay requires authenticated submission")
	r.Pass(s, "VRFY/EXPN", "permanently disabled (user enumeration)")

	if cfg.TLS.MinVersion == "1.2" {
		r.Pass(s, "TLS floor", "TLS 1.2 minimum (SSLv3/TLS 1.0/1.1 never offered)")
	} else {
		r.Pass(s, "TLS floor", "TLS "+cfg.TLS.MinVersion+" minimum")
	}

	if cfg.MailAuth.IsEnabled() {
		if cfg.MailAuth.IsEnforced() {
			r.Pass(s, "SPF/DKIM/DMARC", "enabled and enforcing DMARC policy")
		} else {
			r.Warn(s, "SPF/DKIM/DMARC", "enabled but not enforcing: results are only annotated",
				"set mail_auth.enforce: true once you trust the results")
		}
	} else {
		r.Warn(s, "SPF/DKIM/DMARC", "inbound authentication is disabled",
			"set mail_auth.enabled: true")
	}

	if cfg.RateLimit.Inbound.IsEnabled() {
		r.Pass(s, "inbound rate limit", fmt.Sprintf("%d conn, %d msg, %d rcpt per minute per IP",
			cfg.RateLimit.Inbound.IP.ConnectionsPerMinute,
			cfg.RateLimit.Inbound.IP.MessagesPerMinute,
			cfg.RateLimit.Inbound.IP.RecipientsPerMinute))
	} else {
		r.Fail(s, "inbound rate limit", "disabled: the server has no flood protection",
			"set rate_limit.inbound.enabled: true")
	}

	if cfg.RateLimit.Outbound.IsEnabled() {
		r.Pass(s, "outbound rate limit", fmt.Sprintf("%d msg, %d rcpt per hour per user",
			cfg.RateLimit.Outbound.User.MessagesPerHour,
			cfg.RateLimit.Outbound.User.RecipientsPerHour))
	} else {
		r.Fail(s, "outbound rate limit", "disabled: a compromised account can send without limit",
			"set rate_limit.outbound.enabled: true")
	}

	if cfg.Antispam.IsEnabled() {
		r.Pass(s, "antispam", fmt.Sprintf("tag %.0f, quarantine %.0f, reject %.0f",
			cfg.Antispam.TagScore, cfg.Antispam.QuarantineScore, cfg.Antispam.RejectScore))
	} else {
		r.Warn(s, "antispam", "disabled", "set antispam.enabled: true")
	}

	if cfg.Antivirus.Enabled {
		r.Pass(s, "antivirus", "ClamAV at "+cfg.Antivirus.Socket)
	} else {
		r.Warn(s, "antivirus", "disabled: attachments are not scanned for malware",
			"install ClamAV and set antivirus.enabled: true")
	}

	if cfg.Reputation.IsEnabled() {
		r.Pass(s, "reputation", "outbound sender scoring enabled")
	} else {
		r.Warn(s, "reputation", "disabled: no compromised-account containment",
			"set reputation.enabled: true")
	}

	// Brute force protection.
	if cfg.Auth.MaxFailures > 20 {
		r.Warn(s, "auth lockout", fmt.Sprintf("%d failures allowed before lockout", cfg.Auth.MaxFailures),
			"lower auth.max_failures to 10 or so")
	} else {
		r.Pass(s, "auth lockout", fmt.Sprintf("%d failures, %d minute lockout",
			cfg.Auth.MaxFailures, cfg.Auth.LockoutMinutes))
	}
}

func auditCredentials(r *Report, cfg *config.Config) {
	const s = "Credentials"

	var noHash, bcryptUsers int
	for _, u := range cfg.Users {
		switch {
		case u.PasswordHash == "":
			noHash++
		case strings.HasPrefix(u.PasswordHash, "$2"):
			bcryptUsers++
		}
	}
	if len(cfg.Users) == 0 {
		r.Skip(s, "mailbox passwords", "no virtual users configured")
	} else if noHash > 0 {
		r.Warn(s, "mailbox passwords",
			fmt.Sprintf("%d of %d users have no password_hash and cannot submit or read mail", noHash, len(cfg.Users)),
			"generate one with: kavira hash-password")
	} else {
		r.Pass(s, "mailbox passwords", fmt.Sprintf("all %d users have a hashed password", len(cfg.Users)))
	}
	if bcryptUsers > 0 {
		r.Warn(s, "hash algorithm",
			fmt.Sprintf("%d users still on bcrypt", bcryptUsers),
			"re-hash with kavira hash-password to move them to argon2id")
	}

	if !cfg.API.Enabled {
		r.Skip(s, "api keys", "the administrative API is disabled")
		return
	}
	weak := 0
	for _, k := range cfg.API.Keys {
		if len(k) < 32 {
			weak++
		}
	}
	if weak > 0 {
		r.Warn(s, "api keys", fmt.Sprintf("%d of %d keys are shorter than 32 characters", weak, len(cfg.API.Keys)),
			"generate keys with: openssl rand -hex 32")
	} else {
		r.Pass(s, "api keys", fmt.Sprintf("%d keys, all of adequate length", len(cfg.API.Keys)))
	}
}

// auditPermissions checks that secrets are not world-readable. It is
// skipped off Linux, where the POSIX mode carries no meaning.
func auditPermissions(r *Report, cfg *config.Config, cfgPath string) {
	const s = "Filesystem"

	if runtime.GOOS == "windows" {
		r.Skip(s, "permissions", "POSIX permissions are not meaningful on this platform")
		return
	}

	check := func(name, path string, maxMode fs.FileMode) {
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				r.Skip(s, name, path+" does not exist yet")
				return
			}
			r.Warn(s, name, err.Error(), "")
			return
		}
		mode := info.Mode().Perm()
		if mode&^maxMode != 0 {
			r.Fail(s, name, fmt.Sprintf("%s is mode %04o, wider than %04o", path, mode, maxMode),
				fmt.Sprintf("chmod %04o %s", maxMode, path))
			return
		}
		r.Pass(s, name, fmt.Sprintf("%s is mode %04o", path, mode))
	}

	// Only paths kavira creates and owns are checked. Inferring the
	// state directory from the queue's parent looked tidy but is
	// wrong the moment an operator points queue.dir at its own
	// volume, and it would then report on a directory kavira does
	// not manage.
	check("config file", cfgPath, 0o640)
	check("queue directory", cfg.Queue.Dir, 0o750)
	check("dkim directory", cfg.DKIM.Dir, 0o700)

	// DKIM private keys are the one secret whose leak lets anyone
	// sign as the domain: they must not be group readable either.
	if entries, err := os.ReadDir(cfg.DKIM.Dir); err == nil {
		bad := 0
		total := 0
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			keys, err := os.ReadDir(filepath.Join(cfg.DKIM.Dir, e.Name()))
			if err != nil {
				continue
			}
			for _, k := range keys {
				if !strings.HasSuffix(k.Name(), ".pem") {
					continue
				}
				total++
				info, err := k.Info()
				if err != nil {
					continue
				}
				if info.Mode().Perm()&0o077 != 0 {
					bad++
				}
			}
		}
		switch {
		case total == 0:
			r.Skip(s, "dkim keys", "no keys generated yet")
		case bad > 0:
			r.Fail(s, "dkim keys", fmt.Sprintf("%d of %d private keys are readable beyond their owner", bad, total),
				"chmod 600 "+cfg.DKIM.Dir+"/*/*.pem")
		default:
			r.Pass(s, "dkim keys", fmt.Sprintf("all %d private keys are owner-only", total))
		}
	} else {
		r.Skip(s, "dkim keys", cfg.DKIM.Dir+" does not exist yet")
	}
}

func auditIdentity(r *Report, cfg *config.Config) {
	const s = "Identity"

	if leaks, why := container.LeaksContainerName(cfg.Server.Hostname); leaks {
		r.Fail(s, "public hostname",
			fmt.Sprintf("%s: %s", cfg.Server.Hostname, why),
			"set server.hostname to the public FQDN of the mail server")
	} else {
		r.Pass(s, "public hostname", cfg.Server.Hostname+" is a public fully qualified name")
	}

	if rt := container.Detect(); rt != container.RuntimeNone {
		if cfg.Container.Enabled {
			r.Pass(s, "container mode", fmt.Sprintf("running under %s, container mode enabled", rt))
		} else {
			r.Warn(s, "container mode",
				fmt.Sprintf("running under %s but container.enabled is false", rt),
				"enable the container section so internal addresses stay out of trace headers")
		}
	} else if cfg.Container.Enabled {
		r.Warn(s, "container mode", "container mode is enabled but no container runtime was detected",
			"disable the container section if this is a physical or virtual machine")
	} else {
		r.Pass(s, "container mode", "not running in a container")
	}

	if len(cfg.Domains) == 0 {
		r.Fail(s, "domains", "no domains configured: the server accepts no mail",
			"add at least one domain")
	} else {
		r.Pass(s, "domains", fmt.Sprintf("%d configured: %s",
			len(cfg.Domains), strings.Join(sortedDomains(cfg.DomainNames()), ", ")))
	}
}
