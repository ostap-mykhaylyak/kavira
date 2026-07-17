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
	"strconv"
	"strings"

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
	Server    Server    `yaml:"server"`
	Listeners Listeners `yaml:"listeners"`
	TLS       TLS       `yaml:"tls"`
	Domains   []Domain  `yaml:"domains"`
	Users     []User    `yaml:"users"`
	API       API       `yaml:"api"`
	Log       Log       `yaml:"log"`

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

// Domain is one hosted mail domain.
type Domain struct {
	Name    string  `yaml:"name"`
	Storage Storage `yaml:"storage"`
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
		API: API{Address: ":8443"},
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
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

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
		default:
			return fmt.Errorf("domain %s: storage.type %q: must be %q or %q",
				d.Name, st.Type, StorageSystemUser, StorageVirtual)
		}
	}
	if len(c.Domains) == 0 {
		c.warnf("no domains configured: kavira will accept no mail")
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
