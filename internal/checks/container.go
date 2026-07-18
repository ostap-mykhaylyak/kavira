package checks

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ostap-mykhaylyak/kavira/internal/config"
	"github.com/ostap-mykhaylyak/kavira/internal/container"
)

// ContainerCheck answers one question: from the outside, does this
// deployment look like a mail server on the metal? Everything it
// checks is something that would otherwise leak the container.
func ContainerCheck(cfg *config.Config) *Report {
	r := &Report{}
	const s = "Container"

	rt := container.Detect()
	switch {
	case rt == container.RuntimeNone && !cfg.Container.Enabled:
		r.Pass(s, "runtime", "not running in a container, container mode off")
	case rt == container.RuntimeNone:
		r.Warn(s, "runtime", "container mode is enabled but no container runtime was detected",
			"disable the container section if this is a physical or virtual machine")
	case !cfg.Container.Enabled:
		r.Fail(s, "runtime", fmt.Sprintf("running under %s but container mode is off: internal addresses may reach outgoing mail", rt),
			"enable the container section and set public_ip")
	default:
		r.Pass(s, "runtime", fmt.Sprintf("running under %s, container mode enabled", rt))
		if cfg.Container.Type != "" && !strings.EqualFold(cfg.Container.Type, string(rt)) {
			r.Warn(s, "runtime type",
				fmt.Sprintf("configured as %q but detected %s", cfg.Container.Type, rt), "")
		}
	}

	// --- public identity ---
	checkPublicIdentity(r, cfg, s)

	// --- addresses ---
	checkAddresses(r, cfg, s)

	// --- ports ---
	checkPorts(r, cfg, s)

	// --- storage ---
	checkStorage(r, cfg, s)

	return r
}

func checkPublicIdentity(r *Report, cfg *config.Config, s string) {
	if leaks, why := container.LeaksContainerName(cfg.Server.Hostname); leaks {
		r.Fail(s, "public hostname", fmt.Sprintf("%s: %s", cfg.Server.Hostname, why),
			"the SMTP banner shows this name to every peer: set it to the public FQDN")
	} else {
		r.Pass(s, "public hostname", cfg.Server.Hostname)
	}
	// The banner is built from the same value, so state the result.
	r.Pass(s, "SMTP banner", fmt.Sprintf("220 %s ESMTP Kavira", cfg.Server.Hostname))

	if !cfg.Container.Enabled {
		r.Skip(s, "trace headers", "container mode is off, addresses are recorded as they are")
		return
	}
	id := container.Identity{
		Enabled:    true,
		Hostname:   cfg.Server.Hostname,
		PublicIP:   cfg.Container.PublicIP,
		InternalIP: cfg.Container.InternalIP,
	}
	// Demonstrate the masking rather than assert it: an example is
	// what the operator will actually recognize in a header.
	internal := cfg.Container.InternalIP
	if internal == "" {
		internal = "10.1.0.20"
	}
	if masked := id.MaskIP(internal); masked == cfg.Container.PublicIP {
		r.Pass(s, "trace headers",
			fmt.Sprintf("internal source %s is recorded as %s", internal, masked))
	} else {
		r.Fail(s, "trace headers",
			fmt.Sprintf("internal source %s would be recorded as %s", internal, masked),
			"set container.public_ip to the address the world sees")
	}
	if masked := id.MaskIP("198.51.100.7"); masked != "198.51.100.7" {
		r.Fail(s, "inbound source addresses",
			"public sender addresses are being masked, which destroys inbound traceability", "")
	} else {
		r.Pass(s, "inbound source addresses", "public sender addresses are preserved")
	}
}

func checkAddresses(r *Report, cfg *config.Config, s string) {
	if !cfg.Container.Enabled {
		return
	}
	local, err := container.LocalAddresses()
	if err != nil {
		r.Skip(s, "addresses", "cannot enumerate interfaces: "+err.Error())
		return
	}
	has := func(ip string) bool {
		for _, a := range local {
			if a == ip {
				return true
			}
		}
		return false
	}

	switch {
	case has(cfg.Container.PublicIP):
		r.Pass(s, "public address", cfg.Container.PublicIP+" is bound directly on this machine")
	default:
		// This is the normal bridged/NAT case, not an error: the
		// public address lives on the host and is forwarded in.
		r.Pass(s, "public address",
			cfg.Container.PublicIP+" is not bound locally: traffic arrives through forwarding (bridged/NAT)")
	}

	if cfg.Container.InternalIP == "" {
		r.Skip(s, "internal address", "container.internal_ip is not declared")
	} else if has(cfg.Container.InternalIP) {
		r.Pass(s, "internal address", cfg.Container.InternalIP+" is bound on this machine")
	} else {
		r.Warn(s, "internal address",
			cfg.Container.InternalIP+" is declared but not bound on any interface",
			"correct container.internal_ip, or remove it")
	}
}

// checkPorts probes the listeners the deployment declares, so a
// missing LXD proxy device or firewall rule shows up here rather than
// as mail that silently never arrives.
func checkPorts(r *Report, cfg *config.Config, s string) {
	ports := []struct {
		name string
		addr string
	}{
		{"smtp", cfg.Listeners.SMTP.Address},
		{"smtps", cfg.Listeners.SMTPS.Address},
		{"submission", cfg.Listeners.Submission.Address},
		{"imap", cfg.Listeners.IMAP.Address},
		{"imaps", cfg.Listeners.IMAPS.Address},
		{"pop3", cfg.Listeners.POP3.Address},
		{"pop3s", cfg.Listeners.POP3S.Address},
	}
	var enabled, reachable []string
	for _, p := range ports {
		if p.addr == "" {
			continue
		}
		enabled = append(enabled, p.name)
		host, port, err := net.SplitHostPort(p.addr)
		if err != nil {
			continue
		}
		if host == "" || host == "0.0.0.0" || host == "::" {
			host = "127.0.0.1"
		}
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 3*time.Second)
		if err == nil {
			conn.Close()
			reachable = append(reachable, p.name)
		}
	}

	if len(enabled) == 0 {
		r.Fail(s, "listeners", "no listener is enabled", "configure at least the smtp listener")
		return
	}
	r.Pass(s, "listeners enabled", strings.Join(enabled, ", "))
	switch {
	case len(reachable) == 0:
		r.Warn(s, "listeners reachable", "none answered locally: the daemon is probably not running",
			"start kavira, then run this check again")
	case len(reachable) < len(enabled):
		var missing []string
		for _, e := range enabled {
			found := false
			for _, rr := range reachable {
				if rr == e {
					found = true
				}
			}
			if !found {
				missing = append(missing, e)
			}
		}
		r.Warn(s, "listeners reachable",
			fmt.Sprintf("%s answered, %s did not", strings.Join(reachable, ", "), strings.Join(missing, ", ")),
			"a listener without a TLS certificate does not start; check the service log")
	default:
		r.Pass(s, "listeners reachable", strings.Join(reachable, ", "))
	}
}

// checkStorage reports where mail actually lands, which in a
// container is usually a bind mount or a ZFS dataset.
func checkStorage(r *Report, cfg *config.Config, s string) {
	seen := map[string]bool{}
	var roots []string
	for _, u := range cfg.Users {
		if u.Maildir == "" {
			continue
		}
		root := u.Maildir
		if !seen[root] {
			seen[root] = true
			roots = append(roots, root)
		}
	}
	for _, d := range cfg.Domains {
		if d.Storage.Type == config.StorageSystemUser {
			p := d.Storage.MaildirPath()
			if p != "" && !seen[p] {
				seen[p] = true
				roots = append(roots, p)
			}
		}
	}
	if len(roots) == 0 {
		r.Skip(s, "mail storage", "no mailbox paths configured")
		return
	}
	if len(roots) > 3 {
		roots = append(roots[:3], fmt.Sprintf("and %d more", len(roots)-3))
	}
	r.Pass(s, "mail storage", strings.Join(roots, ", "))
	r.Pass(s, "queue and keys",
		fmt.Sprintf("queue %s, dkim keys %s", cfg.Queue.Dir, cfg.DKIM.Dir))
	r.Warn(s, "backups",
		"kavira does not take backups itself",
		"snapshot the mail storage, "+cfg.Queue.Dir+" and "+cfg.DKIM.Dir+
			" with LXD/ZFS snapshots, and keep a copy of the configuration")
}
