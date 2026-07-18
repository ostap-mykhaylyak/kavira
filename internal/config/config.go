// Package config loads and validates the kavira YAML configuration.
//
// Load never returns a partially usable config: hard errors abort the
// load, soft issues are collected in Config.Warnings so the daemon can
// log them and keep going. Defaults follow the secure-by-default rule:
// anything not explicitly enabled stays off, and an insecure setup
// (e.g. the admin API without keys) is a hard error, not a warning.
package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ostap-mykhaylyak/kavira/internal/blacklist"
	"github.com/ostap-mykhaylyak/kavira/internal/paths"
	"gopkg.in/yaml.v3"
)

// Storage types for a domain's mailboxes.
const (
	// StorageSystemUser delivers to a real Linux user's Maildir,
	// honoring UID/GID and POSIX permissions.
	StorageSystemUser = "system_user"
	// StorageVirtual delivers to virtual mailboxes defined in users.
	StorageVirtual = "virtual"
)

// Config is the root of /etc/kavira/config.yaml.
type Config struct {
	Server     Server     `yaml:"server"`
	Listeners  Listeners  `yaml:"listeners"`
	TLS        TLS        `yaml:"tls"`
	SMTP       SMTP       `yaml:"smtp"`
	MailAuth   MailAuth   `yaml:"mail_auth"`
	Auth       Auth       `yaml:"auth"`
	Queue      Queue      `yaml:"queue"`
	DKIM       DKIM       `yaml:"dkim"`
	Antispam   Antispam   `yaml:"antispam"`
	Antivirus  Antivirus  `yaml:"antivirus"`
	Blacklist  Blacklist  `yaml:"blacklist"`
	Reputation Reputation `yaml:"reputation"`
	Container  Container  `yaml:"container"`
	RateLimit  RateLimit  `yaml:"rate_limit"`
	// DomainsDir holds one file per hosted domain. Domains are kept
	// out of this file so a provisioning script can add or remove one
	// without rewriting the server configuration.
	DomainsDir string `yaml:"domains_dir"`

	// Domains and Users are assembled from DomainsDir, never written
	// here. The yaml tags exist only so a configuration written for an
	// older layout gets a clear migration error instead of the
	// decoder's "field not found".
	Domains []Domain `yaml:"domains"`
	Users   []User   `yaml:"users"`
	API     API      `yaml:"api"`
	Log     Log      `yaml:"log"`

	// Warnings collects non-fatal findings from validation.
	Warnings []string `yaml:"-"`
}

// Server holds global daemon settings.
type Server struct {
	// Hostname is the public identity of this server (SMTP banner,
	// Received headers, default TLS certificate selection). It must
	// never leak an internal/container name.
	Hostname string `yaml:"hostname"`
	// Workers caps concurrent protocol sessions. 0 means default.
	Workers int `yaml:"workers"`
}

// Listener is one network endpoint. An empty address disables it.
type Listener struct {
	Address string `yaml:"address"`
}

// Listeners enumerates every protocol endpoint kavira can serve.
type Listeners struct {
	SMTP       Listener `yaml:"smtp"`
	SMTPS      Listener `yaml:"smtps"`
	Submission Listener `yaml:"submission"`
	IMAP       Listener `yaml:"imap"`
	IMAPS      Listener `yaml:"imaps"`
	POP3       Listener `yaml:"pop3"`
	POP3S      Listener `yaml:"pop3s"`
}

// TLS configures certificate loading and protocol floors.
type TLS struct {
	// CertRoot is the Let's Encrypt live directory. Certificates are
	// wildcards on the configured domain: <cert_root>/<domain>/.
	CertRoot string `yaml:"cert_root"`
	// MinVersion is "1.2" or "1.3". Anything older is never offered.
	MinVersion string `yaml:"min_version"`
	// ExpiryWarnDays triggers expiry warnings this many days before
	// NotAfter. 0 means default.
	ExpiryWarnDays int `yaml:"expiry_warn_days"`
}

// SMTP holds protocol tunables for the SMTP server.
type SMTP struct {
	// MaxSize is the maximum message size in bytes (EHLO SIZE).
	MaxSize int64 `yaml:"max_size"`
	// MaxRecipients caps RCPT commands per message.
	MaxRecipients int `yaml:"max_recipients"`
}

// MailAuth configures the inbound authentication pipeline (SPF,
// DKIM, DMARC) on port 25. Both switches default to on.
type MailAuth struct {
	// Enabled runs the checks and stamps Authentication-Results.
	Enabled *bool `yaml:"enabled"`
	// Enforce applies DMARC reject/quarantine dispositions. When
	// false, results are only annotated and logged.
	Enforce *bool `yaml:"enforce"`
}

// IsEnabled reports whether the pipeline runs at all.
func (m MailAuth) IsEnabled() bool { return m.Enabled == nil || *m.Enabled }

// IsEnforced reports whether DMARC policies are applied.
func (m MailAuth) IsEnforced() bool { return m.Enforce == nil || *m.Enforce }

// Auth configures the brute force protections.
type Auth struct {
	// MaxFailures locks a user/IP after this many failed attempts.
	MaxFailures int `yaml:"max_failures"`
	// LockoutMinutes is how long the lockout lasts.
	LockoutMinutes int `yaml:"lockout_minutes"`
}

// Queue configures the outbound queue.
type Queue struct {
	// Dir is the on-disk queue directory.
	Dir string `yaml:"dir"`
	// MaxAttempts caps transient retries before bouncing.
	MaxAttempts int `yaml:"max_attempts"`
}

// DKIM configures outbound signing.
type DKIM struct {
	// Dir holds the per-domain signing keys
	// (<dir>/<domain>/<selector>.pem). Keys are created by
	// `kavira generate-dkim`.
	Dir string `yaml:"dir"`
}

// Antispam configures the scoring engine on inbound mail.
type Antispam struct {
	Enabled *bool `yaml:"enabled"`
	// BayesFile is the on-disk training corpus.
	BayesFile string `yaml:"bayes_file"`
	// TagScore stamps X-Spam-Status: Yes at or above this score.
	TagScore float64 `yaml:"tag_score"`
	// QuarantineScore delivers into the Spam folder at or above.
	QuarantineScore float64 `yaml:"quarantine_score"`
	// RejectScore refuses the message at DATA at or above.
	RejectScore float64 `yaml:"reject_score"`
	// RejectExecutables refuses messages carrying an executable
	// attachment outright, whatever the score.
	RejectExecutables *bool `yaml:"reject_executables"`
}

// IsEnabled reports whether inbound scoring runs.
func (a Antispam) IsEnabled() bool { return a.Enabled == nil || *a.Enabled }

// RejectsExecutables reports whether executable attachments are
// refused.
func (a Antispam) RejectsExecutables() bool {
	return a.RejectExecutables == nil || *a.RejectExecutables
}

// Antivirus configures the ClamAV connection.
type Antivirus struct {
	Enabled bool `yaml:"enabled"`
	// Socket is a unix socket path or host:port.
	Socket string `yaml:"socket"`
	// TimeoutSeconds bounds one scan.
	TimeoutSeconds int `yaml:"timeout_seconds"`
	// RejectOnError refuses (4xx) when clamd is unreachable, instead
	// of delivering unscanned mail.
	RejectOnError bool `yaml:"reject_on_error"`
}

// Blacklist configures DNSBL and URIBL lookups.
type Blacklist struct {
	Enabled *bool `yaml:"enabled"`
	// DNSBL zones are queried with the connecting IP.
	DNSBL []string `yaml:"dnsbl"`
	// URIBL zones are queried with hostnames found in the body.
	URIBL []string `yaml:"uribl"`
	// RejectListed refuses a connection from a listed IP outright.
	RejectListed bool `yaml:"reject_listed"`
	// CacheMinutes is how long an answer is cached.
	CacheMinutes int `yaml:"cache_minutes"`
}

// IsEnabled reports whether blacklist lookups run.
func (b Blacklist) IsEnabled() bool { return b.Enabled == nil || *b.Enabled }

// Reputation configures outbound sender scoring and warm-up.
type Reputation struct {
	Enabled *bool `yaml:"enabled"`
	// File persists the scores.
	File string `yaml:"file"`
	// WarmUp ramps a new domain's daily sending allowance.
	WarmUp WarmUp `yaml:"warmup"`
}

// IsEnabled reports whether reputation tracking runs.
func (r Reputation) IsEnabled() bool { return r.Enabled == nil || *r.Enabled }

// WarmUp is the sending ramp for new domains.
type WarmUp struct {
	Enabled    bool   `yaml:"enabled"`
	Day1       uint64 `yaml:"day1"`
	Day7       uint64 `yaml:"day7"`
	FullPerDay uint64 `yaml:"full_per_day"`
}

// Container describes an LXD/LXC deployment. From the outside the
// server must look installed on the metal: the public identity comes
// from server.hostname and public_ip, never from the container.
type Container struct {
	Enabled bool `yaml:"enabled"`
	// Type is informational: lxd, lxc, docker.
	Type string `yaml:"type"`
	// PublicIP is the address the world reaches this server on. It
	// replaces internal addresses in outgoing trace headers.
	PublicIP string `yaml:"public_ip"`
	// InternalIP is the container's address on the bridge.
	InternalIP string `yaml:"internal_ip"`
}

// RateLimit configures the flood protections.
type RateLimit struct {
	Inbound  Inbound  `yaml:"inbound"`
	Outbound Outbound `yaml:"outbound"`
}

// Outbound protects against compromised accounts: per-user sending
// caps. Enabled by default.
type Outbound struct {
	Enabled *bool      `yaml:"enabled"`
	User    UserLimits `yaml:"user"`
}

// IsEnabled reports whether outbound rate limiting is active.
func (o Outbound) IsEnabled() bool { return o.Enabled == nil || *o.Enabled }

// UserLimits are per-authenticated-user token bucket rates per hour.
type UserLimits struct {
	MessagesPerHour   int `yaml:"messages_per_hour"`
	RecipientsPerHour int `yaml:"recipients_per_hour"`
}

// Inbound protects against spam floods, SMTP floods, DoS and scans.
// Enabled by default; set enabled: false to switch it off explicitly.
type Inbound struct {
	Enabled *bool    `yaml:"enabled"`
	IP      IPLimits `yaml:"ip"`
}

// IsEnabled reports whether inbound rate limiting is active.
func (i Inbound) IsEnabled() bool { return i.Enabled == nil || *i.Enabled }

// IPLimits are per-source-IP token bucket rates (burst = rate).
type IPLimits struct {
	ConnectionsPerMinute int `yaml:"connections_per_minute"`
	MessagesPerMinute    int `yaml:"messages_per_minute"`
	RecipientsPerMinute  int `yaml:"recipients_per_minute"`
}

// Domain is one hosted mail domain.
type Domain struct {
	Name    string  `yaml:"name"`
	Storage Storage `yaml:"storage"`
	// DKIMSelector names the signing key; empty means "default".
	DKIMSelector string `yaml:"dkim_selector"`
}

// DKIMSelectorFor returns the configured selector of a domain.
func (c *Config) DKIMSelectorFor(domain string) string {
	for _, d := range c.Domains {
		if d.Name == domain {
			return d.DKIMSelector
		}
	}
	return ""
}

// Storage describes where a domain's mailboxes live.
type Storage struct {
	// Type is system_user or virtual. Empty means virtual: mailboxes
	// come from the users list.
	Type string `yaml:"type"`
	// User is the Linux account owning the Maildir (system_user).
	User string `yaml:"user"`
	// Home overrides the account home directory (system_user).
	Home string `yaml:"home"`
	// Maildir is the mailbox path; "{home}" expands to Home.
	Maildir string `yaml:"maildir"`
	// PasswordHash authenticates the bound account for submission
	// (argon2id or bcrypt). Empty means the account cannot submit.
	PasswordHash string `yaml:"password_hash"`
}

// MaildirPath returns the Maildir with "{home}" expanded.
func (s Storage) MaildirPath() string {
	return strings.ReplaceAll(s.Maildir, "{home}", s.Home)
}

// User is one virtual mailbox.
type User struct {
	Email   string `yaml:"email"`
	Type    string `yaml:"type"`
	Maildir string `yaml:"maildir"`
	// PasswordHash authenticates the user for submission (argon2id
	// or bcrypt, never cleartext). Empty means no submission.
	PasswordHash string `yaml:"password_hash"`
}

// PasswordHashFor returns the stored hash for an address, across
// virtual users and system_user domains.
func (c *Config) PasswordHashFor(email string) (string, bool) {
	for _, u := range c.Users {
		if u.Email == email && u.PasswordHash != "" {
			return u.PasswordHash, true
		}
	}
	for _, d := range c.Domains {
		if d.Storage.Type == StorageSystemUser && d.Storage.PasswordHash != "" &&
			email == d.Storage.User+"@"+d.Name {
			return d.Storage.PasswordHash, true
		}
	}
	return "", false
}

// API configures the administrative HTTPS API. Authentication is
// static API keys only (Authorization: Bearer <key>), by design.
type API struct {
	Enabled bool     `yaml:"enabled"`
	Address string   `yaml:"address"`
	Keys    []string `yaml:"keys"`
}

// Log configures the JSON log output.
type Log struct {
	Dir string `yaml:"dir"`
}

// defaults returns a Config pre-filled with the standard layout.
func defaults() *Config {
	return &Config{
		Server: Server{Workers: 50},
		Listeners: Listeners{
			SMTP:       Listener{Address: ":25"},
			SMTPS:      Listener{Address: ":465"},
			Submission: Listener{Address: ":587"},
			IMAP:       Listener{Address: ":143"},
			IMAPS:      Listener{Address: ":993"},
			POP3:       Listener{Address: ":110"},
			POP3S:      Listener{Address: ":995"},
		},
		TLS: TLS{
			CertRoot:       paths.CertRoot,
			MinVersion:     "1.2",
			ExpiryWarnDays: 14,
		},
		SMTP: SMTP{
			MaxSize:       25 * 1024 * 1024,
			MaxRecipients: 100,
		},
		Auth: Auth{
			MaxFailures:    10,
			LockoutMinutes: 15,
		},
		Queue: Queue{
			Dir:         paths.QueueDir,
			MaxAttempts: 10,
		},
		DKIM: DKIM{Dir: paths.DKIMDir},
		Antispam: Antispam{
			BayesFile:       paths.StateDir + "/bayes",
			TagScore:        5,
			QuarantineScore: 10,
			RejectScore:     20,
		},
		Antivirus: Antivirus{
			Socket:         "/var/run/clamav/clamd.ctl",
			TimeoutSeconds: 30,
		},
		Blacklist: Blacklist{
			DNSBL:        blacklist.DefaultDNSBL,
			URIBL:        blacklist.DefaultURIBL,
			CacheMinutes: 60,
		},
		Reputation: Reputation{
			File: paths.StateDir + "/reputation.json",
			WarmUp: WarmUp{
				Enabled:    true,
				Day1:       100,
				Day7:       2000,
				FullPerDay: 50000,
			},
		},
		RateLimit: RateLimit{
			Inbound: Inbound{IP: IPLimits{
				ConnectionsPerMinute: 30,
				MessagesPerMinute:    100,
				RecipientsPerMinute:  500,
			}},
			Outbound: Outbound{User: UserLimits{
				MessagesPerHour:   500,
				RecipientsPerHour: 1000,
			}},
		},
		API: API{Address: ":8443"},
		// DomainsDir is deliberately left empty: it resolves relative
		// to the configuration file, so a staging or test copy is
		// self-contained instead of reaching into /etc.
		Log: Log{Dir: paths.LogDir},
	}
}

// Load reads, parses and validates the configuration at path.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	cfg := defaults()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	// Resolve once, so everything downstream (validation messages,
	// the CLI, the admin API) reports the same directory.
	cfg.DomainsDir = cfg.domainsDir(path)

	// Domains moved out of this file. Say so plainly rather than
	// silently ignoring entries the operator believes are live.
	if len(cfg.Domains) > 0 || len(cfg.Users) > 0 {
		return nil, fmt.Errorf("%s: domains and users now live in one file per domain under %s; "+
			"move each domain into %s/<domain>.yaml and remove the domains/users keys here",
			path, cfg.DomainsDir, cfg.DomainsDir)
	}

	if err := cfg.loadDomains(cfg.DomainsDir); err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// domainsDir resolves the domains directory: the configured value, or
// a "domains" directory beside the main configuration file. Deriving
// it from the config path keeps a test or a staging copy entirely
// self-contained.
func (c *Config) domainsDir(cfgPath string) string {
	if c.DomainsDir != "" {
		return c.DomainsDir
	}
	return filepath.Join(filepath.Dir(cfgPath), "domains")
}

// DomainsDirFor exposes the resolved domains directory to callers that
// only have the config path (the CLI).
func DomainsDirFor(cfg *Config, cfgPath string) string { return cfg.domainsDir(cfgPath) }

// DomainNames returns the configured domain names, in file order.
func (c *Config) DomainNames() []string {
	names := make([]string, len(c.Domains))
	for i, d := range c.Domains {
		names[i] = d.Name
	}
	return names
}

// HasDomain reports whether name is a configured domain.
func (c *Config) HasDomain(name string) bool {
	for _, d := range c.Domains {
		if d.Name == name {
			return true
		}
	}
	return false
}

func (c *Config) warnf(format string, args ...any) {
	c.Warnings = append(c.Warnings, fmt.Sprintf(format, args...))
}

func (c *Config) validate() error {
	// --- server ---
	c.Server.Hostname = normalizeHost(c.Server.Hostname)
	if c.Server.Hostname == "" {
		return fmt.Errorf("server.hostname is required")
	}
	if !strings.Contains(c.Server.Hostname, ".") {
		return fmt.Errorf("server.hostname %q: must be a fully qualified name", c.Server.Hostname)
	}
	if c.Server.Workers == 0 {
		c.Server.Workers = 50
	}
	if c.Server.Workers < 0 {
		return fmt.Errorf("server.workers: must be positive")
	}

	// --- listeners ---
	for _, l := range []struct {
		name string
		addr string
	}{
		{"smtp", c.Listeners.SMTP.Address},
		{"smtps", c.Listeners.SMTPS.Address},
		{"submission", c.Listeners.Submission.Address},
		{"imap", c.Listeners.IMAP.Address},
		{"imaps", c.Listeners.IMAPS.Address},
		{"pop3", c.Listeners.POP3.Address},
		{"pop3s", c.Listeners.POP3S.Address},
	} {
		if l.addr == "" {
			continue // disabled
		}
		if err := checkAddr(l.addr); err != nil {
			return fmt.Errorf("listeners.%s: %w", l.name, err)
		}
	}

	// --- tls ---
	switch c.TLS.MinVersion {
	case "1.2", "1.3":
	default:
		return fmt.Errorf("tls.min_version %q: must be \"1.2\" or \"1.3\"", c.TLS.MinVersion)
	}
	if c.TLS.ExpiryWarnDays == 0 {
		c.TLS.ExpiryWarnDays = 14
	}
	if c.TLS.ExpiryWarnDays < 0 {
		return fmt.Errorf("tls.expiry_warn_days: must be positive")
	}
	if c.TLS.CertRoot == "" {
		c.TLS.CertRoot = paths.CertRoot
	}

	// --- smtp ---
	if c.SMTP.MaxSize <= 0 {
		return fmt.Errorf("smtp.max_size: must be positive")
	}
	if c.SMTP.MaxRecipients <= 0 {
		return fmt.Errorf("smtp.max_recipients: must be positive")
	}

	// --- auth ---
	if c.Auth.MaxFailures <= 0 {
		return fmt.Errorf("auth.max_failures: must be positive")
	}
	if c.Auth.LockoutMinutes <= 0 {
		return fmt.Errorf("auth.lockout_minutes: must be positive")
	}

	// --- queue ---
	if c.Queue.Dir == "" {
		c.Queue.Dir = paths.QueueDir
	}
	if c.Queue.MaxAttempts <= 0 {
		return fmt.Errorf("queue.max_attempts: must be positive")
	}

	// --- dkim ---
	if c.DKIM.Dir == "" {
		c.DKIM.Dir = paths.DKIMDir
	}

	// --- antispam ---
	if c.Antispam.IsEnabled() {
		a := &c.Antispam
		if a.BayesFile == "" {
			a.BayesFile = paths.StateDir + "/bayes"
		}
		if a.TagScore <= 0 || a.QuarantineScore <= 0 || a.RejectScore <= 0 {
			return fmt.Errorf("antispam: tag_score, quarantine_score and reject_score must be positive")
		}
		// The thresholds must escalate, or the milder action can never
		// be reached and the operator's intent is silently inverted.
		if !(a.TagScore <= a.QuarantineScore && a.QuarantineScore <= a.RejectScore) {
			return fmt.Errorf("antispam: thresholds must satisfy tag_score <= quarantine_score <= reject_score (got %.1f, %.1f, %.1f)",
				a.TagScore, a.QuarantineScore, a.RejectScore)
		}
	}

	// --- antivirus ---
	if c.Antivirus.Enabled {
		if c.Antivirus.Socket == "" {
			return fmt.Errorf("antivirus.enabled requires antivirus.socket")
		}
		if c.Antivirus.TimeoutSeconds <= 0 {
			c.Antivirus.TimeoutSeconds = 30
		}
	}

	// --- blacklist ---
	if c.Blacklist.IsEnabled() {
		if c.Blacklist.CacheMinutes <= 0 {
			c.Blacklist.CacheMinutes = 60
		}
		if len(c.Blacklist.DNSBL) == 0 && len(c.Blacklist.URIBL) == 0 {
			c.warnf("blacklist enabled but no dnsbl/uribl zones configured: no lookups will happen")
		}
	}

	// --- reputation ---
	if c.Reputation.IsEnabled() {
		if c.Reputation.File == "" {
			c.Reputation.File = paths.StateDir + "/reputation.json"
		}
		if w := c.Reputation.WarmUp; w.Enabled {
			if w.Day1 == 0 || w.Day7 == 0 || w.FullPerDay == 0 {
				return fmt.Errorf("reputation.warmup: day1, day7 and full_per_day must be positive")
			}
			if !(w.Day1 <= w.Day7 && w.Day7 <= w.FullPerDay) {
				return fmt.Errorf("reputation.warmup: the ramp must grow (day1 <= day7 <= full_per_day)")
			}
		}
	}

	// --- container ---
	if c.Container.Enabled {
		if c.Container.PublicIP == "" {
			return fmt.Errorf("container.enabled requires container.public_ip: without it kavira cannot keep internal addresses out of trace headers")
		}
		if net.ParseIP(c.Container.PublicIP) == nil {
			return fmt.Errorf("container.public_ip %q: not a valid IP address", c.Container.PublicIP)
		}
		if c.Container.InternalIP != "" && net.ParseIP(c.Container.InternalIP) == nil {
			return fmt.Errorf("container.internal_ip %q: not a valid IP address", c.Container.InternalIP)
		}
		if ip := net.ParseIP(c.Container.PublicIP); ip != nil && (ip.IsPrivate() || ip.IsLoopback()) {
			c.warnf("container.public_ip %s is a private address: outgoing mail will still carry an internal address",
				c.Container.PublicIP)
		}
	}

	// --- rate_limit ---
	if c.RateLimit.Inbound.IsEnabled() {
		ip := c.RateLimit.Inbound.IP
		if ip.ConnectionsPerMinute <= 0 || ip.MessagesPerMinute <= 0 || ip.RecipientsPerMinute <= 0 {
			return fmt.Errorf("rate_limit.inbound.ip: all limits must be positive (or set enabled: false)")
		}
	} else {
		c.warnf("inbound rate limiting is disabled: no flood protection")
	}
	if c.RateLimit.Outbound.IsEnabled() {
		u := c.RateLimit.Outbound.User
		if u.MessagesPerHour <= 0 || u.RecipientsPerHour <= 0 {
			return fmt.Errorf("rate_limit.outbound.user: all limits must be positive (or set enabled: false)")
		}
	} else {
		c.warnf("outbound rate limiting is disabled: no compromised-account protection")
	}

	// --- domains ---
	seen := map[string]bool{}
	for i := range c.Domains {
		d := &c.Domains[i]
		d.Name = normalizeHost(d.Name)
		if d.Name == "" {
			return fmt.Errorf("domains[%d]: name is required", i)
		}
		if !strings.Contains(d.Name, ".") {
			return fmt.Errorf("domains[%d] %q: must contain a dot", i, d.Name)
		}
		if seen[d.Name] {
			return fmt.Errorf("domains[%d] %q: duplicate domain", i, d.Name)
		}
		seen[d.Name] = true

		st := &d.Storage
		switch st.Type {
		case "", StorageVirtual:
			// Mailboxes come from the users list.
		case StorageSystemUser:
			if st.User == "" {
				return fmt.Errorf("domain %s: storage.user is required for system_user", d.Name)
			}
			if st.Home == "" {
				st.Home = "/home/" + st.User
			}
			if st.Maildir == "" {
				st.Maildir = "{home}/mail"
			}
			if st.PasswordHash != "" && !knownHash(st.PasswordHash) {
				return fmt.Errorf("domain %s: storage.password_hash: unknown format (argon2id or bcrypt required, never cleartext)", d.Name)
			}
		default:
			return fmt.Errorf("domain %s: storage.type %q: must be %q or %q",
				d.Name, st.Type, StorageSystemUser, StorageVirtual)
		}
	}
	if len(c.Domains) == 0 {
		c.warnf("no domain files found in %s: kavira will accept no mail", c.DomainsDir)
	}

	// --- users ---
	for i := range c.Users {
		u := &c.Users[i]
		u.Email = strings.ToLower(strings.TrimSpace(u.Email))
		at := strings.LastIndex(u.Email, "@")
		if at <= 0 || at == len(u.Email)-1 {
			return fmt.Errorf("users[%d] %q: invalid email address", i, u.Email)
		}
		if u.Type == "" {
			u.Type = StorageVirtual
		}
		if u.Type != StorageVirtual {
			return fmt.Errorf("user %s: type %q: only %q is valid here", u.Email, u.Type, StorageVirtual)
		}
		if u.Maildir == "" {
			return fmt.Errorf("user %s: maildir is required", u.Email)
		}
		if dom := u.Email[at+1:]; !c.HasDomain(dom) {
			c.warnf("user %s: domain %s is not configured", u.Email, dom)
		}
		if u.PasswordHash != "" && !knownHash(u.PasswordHash) {
			return fmt.Errorf("user %s: password_hash: unknown format (argon2id or bcrypt required, never cleartext)", u.Email)
		}
	}

	// --- api ---
	if c.API.Enabled {
		if c.API.Address == "" {
			c.API.Address = ":8443"
		}
		if err := checkAddr(c.API.Address); err != nil {
			return fmt.Errorf("api.address: %w", err)
		}
		// Secure by default: an admin API without credentials is an
		// open door, refuse to start rather than warn.
		if len(c.API.Keys) == 0 {
			return fmt.Errorf("api.enabled requires at least one api.keys entry")
		}
		for i, k := range c.API.Keys {
			if len(k) < 32 {
				c.warnf("api.keys[%d]: shorter than 32 characters, consider a stronger key", i)
			}
		}
	}

	// --- log ---
	if c.Log.Dir == "" {
		c.Log.Dir = paths.LogDir
	}

	return nil
}

// knownHash reports whether a password hash uses a supported format.
func knownHash(h string) bool {
	return strings.HasPrefix(h, "$argon2id$") ||
		strings.HasPrefix(h, "$2a$") || strings.HasPrefix(h, "$2b$") || strings.HasPrefix(h, "$2y$")
}

// normalizeHost lowercases and strips whitespace and a trailing dot.
func normalizeHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

// checkAddr validates a listen address of the form [host]:port.
func checkAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid address %q: %w", addr, err)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid port %q", port)
	}
	if host != "" {
		if ip := net.ParseIP(host); ip == nil {
			return fmt.Errorf("invalid host %q: must be an IP or empty", host)
		}
	}
	return nil
}
