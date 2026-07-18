// Package paths centralizes the default filesystem layout of kavira.
//
// Every location can be overridden (config file via --config, log dir
// via the config itself), but the defaults below are what the systemd
// unit, the Makefile and the bootstrap skeleton agree on.
package paths

const (
	// ConfigDir holds the main configuration.
	ConfigDir = "/etc/kavira"
	// ConfigFile is the main configuration file.
	ConfigFile = ConfigDir + "/config.yaml"
	// DomainsDir holds one YAML file per hosted domain, so adding or
	// removing a domain never touches the server configuration.
	DomainsDir = ConfigDir + "/domains"

	// LogDir is the default JSON log directory (config log.dir).
	LogDir = "/var/log/kavira"

	// StateDir holds persistent runtime state.
	StateDir = "/var/lib/kavira"
	// QueueDir holds the outbound SMTP queue (from M2 on).
	QueueDir = StateDir + "/queue"
	// DKIMDir holds per-domain DKIM keys (from M3 on).
	DKIMDir = StateDir + "/dkim"

	// RunDir is the runtime directory (systemd RuntimeDirectory).
	RunDir = "/run/kavira"
	// Pidfile is written by the daemon and read by stop/reload.
	Pidfile = RunDir + "/kavira.pid"

	// CertRoot is the default Let's Encrypt live directory. Kavira
	// only ever looks up <CertRoot>/<configured-domain>/, never a
	// per-subdomain directory: certificates are wildcards issued on
	// the configured (base) domain.
	CertRoot = "/etc/letsencrypt/live"
)
