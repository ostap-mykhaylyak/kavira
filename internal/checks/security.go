package checks

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ostap-mykhaylyak/kavira/internal/blacklist"
	"github.com/ostap-mykhaylyak/kavira/internal/config"
	"github.com/ostap-mykhaylyak/kavira/internal/dkim"
	ktls "github.com/ostap-mykhaylyak/kavira/internal/tls"
)

// dialTimeout bounds every network probe: a check that hangs is
// worse than one that fails.
const dialTimeout = 10 * time.Second

// SecurityCheck exercises the live deployment. host overrides the
// address probed for SMTP (defaults to the configured hostname), which
// is what lets the check run against localhost during installation.
func SecurityCheck(cfg *config.Config, probeHost string) *Report {
	r := &Report{}
	if probeHost == "" {
		probeHost = cfg.Server.Hostname
	}
	checkTLSCertificates(r, cfg)
	checkOpenRelay(r, cfg, probeHost)
	checkDNS(r, cfg)
	checkReverseDNS(r, cfg)
	checkBlacklists(r, cfg)
	return r
}

func checkTLSCertificates(r *Report, cfg *config.Config) {
	const s = "TLS"

	store, warns := ktls.New(ktls.Params{
		CertRoot:       cfg.TLS.CertRoot,
		Hostname:       cfg.Server.Hostname,
		Domains:        cfg.DomainNames(),
		MinVersion:     cfg.TLS.MinVersion,
		ExpiryWarnDays: cfg.TLS.ExpiryWarnDays,
	})
	loaded := store.Loaded()

	if len(loaded) == 0 {
		r.Fail(s, "certificates", "no certificate loaded: submission, IMAP, POP3 and the API will not start",
			fmt.Sprintf("obtain a wildcard certificate into %s/<domain>/", cfg.TLS.CertRoot))
	} else {
		r.Pass(s, "certificates", fmt.Sprintf("%d loaded: %s", len(loaded), strings.Join(loaded, ", ")))
	}
	for _, w := range warns {
		// Expiry warnings and missing certificates arrive here.
		if strings.Contains(w, "EXPIRED") {
			r.Fail(s, "certificate validity", w, "renew the certificate now")
		} else if strings.Contains(w, "expires in") {
			r.Warn(s, "certificate expiry", w, "check that automatic renewal is working")
		} else {
			r.Warn(s, "certificate", w, "")
		}
	}

	// Every hosted domain needs a certificate its clients can use.
	for _, d := range sortedDomains(cfg.DomainNames()) {
		found := false
		for _, l := range loaded {
			if l == d {
				found = true
			}
		}
		if !found {
			r.Warn(s, "certificate for "+d, "no certificate loaded for this domain",
				fmt.Sprintf("issue a wildcard certificate for %s into %s/%s/", d, cfg.TLS.CertRoot, d))
		}
	}
}

// checkOpenRelay performs a real relay attempt against the running
// server: reading the configuration is not evidence, a 554 is.
func checkOpenRelay(r *Report, cfg *config.Config, probeHost string) {
	const s = "Open relay"

	addr := cfg.Listeners.SMTP.Address
	if addr == "" {
		r.Skip(s, "relay test", "the SMTP listener is disabled")
		return
	}
	// Turn a bind address into something dialable.
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		r.Warn(s, "relay test", "cannot parse listener address "+addr, "")
		return
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = probeHost
	}
	target := net.JoinHostPort(host, port)

	conn, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		r.Warn(s, "relay test", fmt.Sprintf("cannot connect to %s: %v", target, err),
			"start the daemon, or pass --host to probe a different address")
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(dialTimeout))

	br := bufio.NewReader(conn)
	read := func() string {
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return ""
			}
			if len(line) >= 4 && line[3] == ' ' {
				return strings.TrimSpace(line)
			}
		}
	}
	send := func(cmd string) string {
		fmt.Fprintf(conn, "%s\r\n", cmd)
		return read()
	}

	banner := read()
	if banner == "" {
		r.Warn(s, "relay test", "no banner received", "")
		return
	}
	// The banner must carry the public hostname, never a container
	// name — this is what the outside world sees first.
	if strings.Contains(banner, cfg.Server.Hostname) {
		r.Pass(s, "banner", banner)
	} else {
		r.Fail(s, "banner", fmt.Sprintf("banner does not carry the configured hostname: %q", banner),
			"set server.hostname to the public name")
	}

	send("EHLO relay-test.invalid")
	send("MAIL FROM:<probe@relay-test.invalid>")
	// The decisive test: a recipient at a domain we do not host.
	reply := send("RCPT TO:<victim@relay-test-external.invalid>")
	switch {
	case strings.HasPrefix(reply, "554"), strings.HasPrefix(reply, "550"),
		strings.HasPrefix(reply, "553"), strings.HasPrefix(reply, "551"):
		r.Pass(s, "external relay refused", reply)
	case reply == "":
		r.Warn(s, "external relay", "no reply to RCPT", "")
	default:
		r.Fail(s, "OPEN RELAY", "the server accepted a foreign recipient without authentication: "+reply,
			"this server can be used to send spam; stop it and report the issue")
	}

	// AUTH must not be offered in the clear on port 25.
	if reply := send("AUTH LOGIN " + base64.StdEncoding.EncodeToString([]byte("x"))); strings.HasPrefix(reply, "334") || strings.HasPrefix(reply, "235") {
		r.Fail(s, "AUTH on port 25", "the inbound port accepts authentication: "+reply,
			"authentication belongs on submission (587/465) only")
	} else {
		r.Pass(s, "AUTH on port 25", "refused: "+reply)
	}

	for _, cmd := range []string{"VRFY postmaster", "EXPN staff"} {
		reply := send(cmd)
		name := strings.Fields(cmd)[0]
		if strings.HasPrefix(reply, "502") || strings.HasPrefix(reply, "252") {
			r.Pass(s, name+" disabled", reply)
		} else {
			r.Fail(s, name, "user enumeration is possible: "+reply, "")
		}
	}
	send("QUIT")
}

// checkDNS verifies the records every hosted domain needs.
func checkDNS(r *Report, cfg *config.Config) {
	const s = "DNS"
	res := net.DefaultResolver
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if len(cfg.Domains) == 0 {
		r.Skip(s, "records", "no domains configured")
		return
	}

	for _, domain := range sortedDomains(cfg.DomainNames()) {
		// --- MX ---
		mxs, err := res.LookupMX(ctx, domain)
		switch {
		case err != nil || len(mxs) == 0:
			r.Fail(s, domain+" MX", "no MX record found: this domain receives no mail",
				fmt.Sprintf("publish: %s. IN MX 10 %s.", domain, cfg.Server.Hostname))
		case len(mxs) == 1 && (mxs[0].Host == "." || mxs[0].Host == ""):
			// RFC 7505 null MX: the domain declares that it accepts
			// no mail at all, which contradicts hosting it here.
			r.Fail(s, domain+" MX", "a null MX (RFC 7505) is published: the domain declares it accepts no mail",
				fmt.Sprintf("replace it with: %s. IN MX 10 %s.", domain, cfg.Server.Hostname))
		default:
			pointsHere := false
			var hosts []string
			for _, mx := range mxs {
				h := strings.TrimSuffix(mx.Host, ".")
				if h == "" {
					continue
				}
				hosts = append(hosts, h)
				if strings.EqualFold(h, cfg.Server.Hostname) {
					pointsHere = true
				}
			}
			switch {
			case pointsHere:
				r.Pass(s, domain+" MX", strings.Join(hosts, ", "))
			case len(hosts) == 0:
				r.Fail(s, domain+" MX", "the MX records name no usable host",
					fmt.Sprintf("publish: %s. IN MX 10 %s.", domain, cfg.Server.Hostname))
			default:
				r.Warn(s, domain+" MX",
					fmt.Sprintf("MX points to %s, not to %s", strings.Join(hosts, ", "), cfg.Server.Hostname),
					"point the MX at this server, or ignore if mail arrives through a relay")
			}
		}

		// --- SPF ---
		txts, err := res.LookupTXT(ctx, domain)
		spf := ""
		if err == nil {
			for _, t := range txts {
				if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
					spf = t
				}
			}
		}
		switch {
		case spf == "":
			r.Fail(s, domain+" SPF", "no SPF record: receivers cannot tell your mail from a forgery",
				fmt.Sprintf(`publish: %s. IN TXT "v=spf1 mx -all"`, domain))
		case strings.Contains(spf, "+all"):
			r.Fail(s, domain+" SPF", "the record ends in +all, which authorizes the entire internet: "+spf,
				"replace +all with -all")
		case !strings.Contains(spf, "-all") && !strings.Contains(spf, "~all"):
			r.Warn(s, domain+" SPF", "the record has no -all or ~all: "+spf,
				"end the record with -all once you are confident it is complete")
		default:
			r.Pass(s, domain+" SPF", spf)
		}

		// --- DKIM: the published key must match the local one ---
		selector := cfg.DKIMSelectorFor(domain)
		if selector == "" {
			selector = dkim.DefaultSelector
		}
		_, localTXT, localErr := dkim.NewStore(cfg.DKIM.Dir).TXTRecord(domain, selector)
		dkimName := selector + "._domainkey." + domain
		published, pubErr := res.LookupTXT(ctx, dkimName)
		joined := strings.Join(published, "")

		switch {
		case localErr != nil && pubErr != nil:
			r.Warn(s, domain+" DKIM", "no local key and no published record: mail is sent unsigned",
				"generate one with: kavira generate-dkim "+domain)
		case localErr != nil:
			r.Warn(s, domain+" DKIM", "a record is published but no local key exists: signing is impossible",
				"generate the key with: kavira generate-dkim "+domain)
		case pubErr != nil || joined == "":
			r.Fail(s, domain+" DKIM", "a local key exists but nothing is published at "+dkimName,
				fmt.Sprintf("publish: %s. IN TXT %q", dkimName, localTXT))
		case !sameDKIMKey(joined, localTXT):
			r.Fail(s, domain+" DKIM", "the published key does not match the local one: signatures will fail",
				fmt.Sprintf("republish: %s. IN TXT %q", dkimName, localTXT))
		default:
			r.Pass(s, domain+" DKIM", "published key matches the local key ("+selector+")")
		}

		// --- DMARC ---
		dmarcTXT, err := res.LookupTXT(ctx, "_dmarc."+domain)
		dmarc := ""
		if err == nil {
			for _, t := range dmarcTXT {
				if strings.HasPrefix(strings.ToLower(t), "v=dmarc1") {
					dmarc = t
				}
			}
		}
		switch {
		case dmarc == "":
			r.Warn(s, domain+" DMARC", "no DMARC record: nobody enforces your SPF and DKIM",
				fmt.Sprintf(`publish: _dmarc.%s. IN TXT "v=DMARC1; p=quarantine; rua=mailto:postmaster@%s"`, domain, domain))
		case strings.Contains(strings.ToLower(dmarc), "p=none"):
			r.Warn(s, domain+" DMARC", "policy is p=none, which asks receivers to do nothing: "+dmarc,
				"move to p=quarantine, then p=reject, once the reports look clean")
		default:
			r.Pass(s, domain+" DMARC", dmarc)
		}
	}
}

// sameDKIMKey compares the p= public key of two DKIM records,
// ignoring formatting and the order of the other tags.
func sameDKIMKey(a, b string) bool {
	return dkimPublicKey(a) != "" && dkimPublicKey(a) == dkimPublicKey(b)
}

func dkimPublicKey(txt string) string {
	for _, part := range strings.Split(txt, ";") {
		part = strings.TrimSpace(part)
		if v, ok := strings.CutPrefix(part, "p="); ok {
			// DNS may return the value split across strings and with
			// whitespace inserted; both are cosmetic.
			return strings.NewReplacer(" ", "", "\t", "", "\r", "", "\n", "").Replace(v)
		}
	}
	return ""
}

// checkReverseDNS verifies the PTR of the public IP, which large
// receivers check before accepting anything.
func checkReverseDNS(r *Report, cfg *config.Config) {
	const s = "Reverse DNS"
	res := net.DefaultResolver
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// The address to check: the declared public IP, or whatever the
	// hostname resolves to.
	ip := cfg.Container.PublicIP
	if ip == "" {
		addrs, err := res.LookupHost(ctx, cfg.Server.Hostname)
		if err != nil || len(addrs) == 0 {
			r.Fail(s, "hostname resolution", cfg.Server.Hostname+" does not resolve",
				"publish an A record for the mail hostname")
			return
		}
		ip = addrs[0]
		r.Pass(s, "hostname resolution", cfg.Server.Hostname+" resolves to "+strings.Join(addrs, ", "))
	}

	names, err := res.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		r.Fail(s, "PTR record", "no reverse DNS for "+ip+": most large receivers will refuse your mail",
			fmt.Sprintf("ask your provider to set the PTR of %s to %s", ip, cfg.Server.Hostname))
		return
	}
	matched := false
	var clean []string
	for _, n := range names {
		n = strings.TrimSuffix(n, ".")
		clean = append(clean, n)
		if strings.EqualFold(n, cfg.Server.Hostname) {
			matched = true
		}
	}
	if !matched {
		r.Fail(s, "PTR record",
			fmt.Sprintf("%s reverses to %s, not to %s", ip, strings.Join(clean, ", "), cfg.Server.Hostname),
			fmt.Sprintf("set the PTR of %s to %s (forward-confirmed reverse DNS)", ip, cfg.Server.Hostname))
		return
	}
	// Forward-confirmed: the name must point back to the same IP.
	back, err := res.LookupHost(ctx, cfg.Server.Hostname)
	confirmed := false
	for _, b := range back {
		if b == ip {
			confirmed = true
		}
	}
	if err == nil && confirmed {
		r.Pass(s, "PTR record", ip+" <-> "+cfg.Server.Hostname+" (forward-confirmed)")
	} else {
		r.Warn(s, "PTR record", ip+" reverses to "+cfg.Server.Hostname+" but the name does not resolve back to it",
			"make the A record and the PTR agree")
	}
}

func checkBlacklists(r *Report, cfg *config.Config) {
	const s = "Blacklists"

	if !cfg.Blacklist.IsEnabled() || len(cfg.Blacklist.DNSBL) == 0 {
		r.Skip(s, "listing", "blacklist lookups are disabled")
		return
	}
	ip := cfg.Container.PublicIP
	if ip == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		addrs, err := net.DefaultResolver.LookupHost(ctx, cfg.Server.Hostname)
		if err != nil || len(addrs) == 0 {
			r.Skip(s, "listing", "cannot determine the public IP")
			return
		}
		ip = addrs[0]
	}

	c := blacklist.New(cfg.Blacklist.DNSBL, nil, time.Minute)
	if listed, zones := c.ListedIP(ip); listed {
		r.Fail(s, "sending IP", fmt.Sprintf("%s is listed on %s", ip, strings.Join(zones, ", ")),
			"request delisting at the listing operators, and find out what caused it before you do")
	} else {
		r.Pass(s, "sending IP", ip+" is not listed on "+fmt.Sprint(len(cfg.Blacklist.DNSBL))+" checked lists")
	}
}
