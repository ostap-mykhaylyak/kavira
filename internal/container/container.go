// Package container keeps kavira's public identity clean when it runs
// inside an LXD/LXC container.
//
// From the outside, a containerized kavira must be indistinguishable
// from one installed on the metal: the SMTP banner, the Received
// headers, the EHLO name and even the Maildir filenames carry the
// configured public hostname, never the container's own name, and
// never an address from the internal bridge network.
//
// The daemon already takes every public name from server.hostname, so
// this package covers what is left: detecting the runtime, masking
// private addresses that would otherwise be recorded in a trace
// header, and flagging a configuration whose hostname is itself a
// container name.
package container

import (
	"net"
	"os"
	"strings"
)

// Runtime is the container technology kavira is running under.
type Runtime string

const (
	RuntimeNone   Runtime = "none"
	RuntimeLXC    Runtime = "lxc"
	RuntimeLXD    Runtime = "lxd"
	RuntimeDocker Runtime = "docker"
	RuntimeOther  Runtime = "container"
)

// Detect reports the container runtime, best effort. It reads only
// well-known marker files, so it is safe (and useless) off Linux.
func Detect() Runtime {
	// systemd exports this for every container it can identify.
	if v := os.Getenv("container"); v != "" {
		switch strings.ToLower(v) {
		case "lxc":
			return RuntimeLXC
		case "lxc-libvirt", "systemd-nspawn", "podman":
			return RuntimeOther
		default:
			return RuntimeOther
		}
	}
	if _, err := os.Stat("/dev/.lxd-mounts"); err == nil {
		return RuntimeLXD
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return RuntimeDocker
	}
	// Inside LXC the init cgroup path mentions the container.
	if b, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(b)
		switch {
		case strings.Contains(s, "/lxc/"):
			return RuntimeLXC
		case strings.Contains(s, "/docker/"):
			return RuntimeDocker
		}
	}
	return RuntimeNone
}

// Identity is the public face of a containerized deployment.
type Identity struct {
	// Enabled turns the masking on.
	Enabled bool
	// Hostname is the public name (server.hostname).
	Hostname string
	// PublicIP is the address the world sees.
	PublicIP string
	// InternalIP is the container's address on the bridge.
	InternalIP string
}

// MaskIP returns the address to record in a trace header for ip.
// A private or loopback address is replaced by the public IP, so a
// message relayed onward never carries the internal topology of the
// host — a webmail on the internal bridge submitting through kavira
// is the common case. Public addresses pass through untouched: the
// real source of inbound mail is genuinely useful information.
func (id Identity) MaskIP(ip string) string {
	if !id.Enabled || id.PublicIP == "" {
		return ip
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return id.PublicIP
	}
	if isInternal(parsed) {
		return id.PublicIP
	}
	return ip
}

// isInternal reports whether an address belongs to a range that must
// never appear in a public trace header.
func isInternal(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified()
}

// LeaksContainerName reports whether a configured hostname looks like
// a container's own name rather than a public mail hostname, and why.
// Getting this wrong is visible in every SMTP banner, so it is worth
// refusing to be subtle about it.
func LeaksContainerName(hostname string) (bool, string) {
	h := strings.ToLower(strings.TrimSpace(hostname))
	if h == "" {
		return false, ""
	}
	// LXD publishes containers under .lxd; .local is mDNS.
	for _, suffix := range []string{".lxd", ".local", ".internal", ".localdomain"} {
		if strings.HasSuffix(h, suffix) {
			return true, "hostname ends in " + suffix + ", which is not publicly resolvable"
		}
	}
	if !strings.Contains(h, ".") {
		return true, "hostname is not fully qualified"
	}
	// Matching the machine's own name is the classic mistake: the
	// container is called "mail01" and so is the banner.
	if own, err := os.Hostname(); err == nil {
		if strings.EqualFold(own, h) && !strings.Contains(own, ".") {
			return true, "hostname equals the machine's unqualified name (" + own + ")"
		}
	}
	return false, ""
}

// LocalAddresses lists the addresses bound on this machine, used to
// tell whether a configured public_ip is actually present (direct
// binding) or arrives through port forwarding.
func LocalAddresses() ([]string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			out = append(out, ipnet.IP.String())
		}
	}
	return out, nil
}
