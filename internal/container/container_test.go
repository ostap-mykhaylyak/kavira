package container

import "testing"

func TestMaskInternalAddresses(t *testing.T) {
	id := Identity{Enabled: true, Hostname: "mail.example.com", PublicIP: "203.0.113.10", InternalIP: "10.1.0.20"}

	// Internal sources are replaced: a message relayed onward must
	// not carry the host's private topology.
	for _, ip := range []string{"10.1.0.20", "192.168.1.5", "172.16.0.9", "127.0.0.1", "169.254.1.1"} {
		if got := id.MaskIP(ip); got != "203.0.113.10" {
			t.Errorf("MaskIP(%q) = %q, want the public IP", ip, got)
		}
	}
	// Public sources are preserved: the real origin of inbound mail
	// is genuinely useful and must stay traceable.
	for _, ip := range []string{"198.51.100.7", "8.8.8.8", "2001:db8::1"} {
		if got := id.MaskIP(ip); got != ip {
			t.Errorf("MaskIP(%q) = %q, want it unchanged", ip, got)
		}
	}
	// An unparsable value falls back to the public IP rather than
	// passing something unknown into a header.
	if got := id.MaskIP("not-an-ip"); got != "203.0.113.10" {
		t.Errorf("MaskIP(garbage) = %q", got)
	}
}

func TestMaskDisabledPassesThrough(t *testing.T) {
	id := Identity{Enabled: false, PublicIP: "203.0.113.10"}
	if got := id.MaskIP("10.1.0.20"); got != "10.1.0.20" {
		t.Errorf("with masking off the address must pass through, got %q", got)
	}
	// Enabled but without a public IP there is nothing to mask with.
	id2 := Identity{Enabled: true}
	if got := id2.MaskIP("10.1.0.20"); got != "10.1.0.20" {
		t.Errorf("without a public IP the address must pass through, got %q", got)
	}
}

func TestLeaksContainerName(t *testing.T) {
	cases := []struct {
		hostname string
		leaks    bool
	}{
		{"mail.example.com", false},
		{"mail.studenti.ente.it", false},
		{"container01.lxd", true},
		{"mail.local", true},
		{"mail.internal", true},
		{"srv.localdomain", true},
		{"mail01", true}, // not fully qualified
		{"", false},      // empty is the config validator's problem
	}
	for _, c := range cases {
		got, why := LeaksContainerName(c.hostname)
		if got != c.leaks {
			t.Errorf("LeaksContainerName(%q) = %v (%s), want %v", c.hostname, got, why, c.leaks)
		}
		if got && why == "" {
			t.Errorf("LeaksContainerName(%q) reported a leak with no explanation", c.hostname)
		}
	}
}

func TestDetectDoesNotPanic(t *testing.T) {
	// The result depends on where the tests run; what matters is
	// that detection is safe to call anywhere.
	if got := Detect(); got == "" {
		t.Error("Detect returned an empty runtime")
	}
}

func TestLocalAddresses(t *testing.T) {
	addrs, err := LocalAddresses()
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) == 0 {
		t.Error("expected at least a loopback address")
	}
}
