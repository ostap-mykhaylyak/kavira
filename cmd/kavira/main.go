// kavira - enterprise secure mail server.
//
// Usage:
//
//	kavira start [--config path] [--pidfile path]
//	kavira stop [--pidfile path]
//	kavira reload [--pidfile path]
//	kavira check-config [--config path]
//	kavira version
//
// Planned (later milestones): generate-dkim, security-check, audit,
// container-check.
//
// M0 scaffolding: lifecycle, configuration, JSON logging, TLS/SNI
// certificate store. Protocol servers land from M1 on.
package main

import (
	"bufio"
	stdtls "crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ostap-mykhaylyak/kavira/internal/antispam"
	"github.com/ostap-mykhaylyak/kavira/internal/antivirus"
	"github.com/ostap-mykhaylyak/kavira/internal/api"
	"github.com/ostap-mykhaylyak/kavira/internal/auth"
	"github.com/ostap-mykhaylyak/kavira/internal/blacklist"
	"github.com/ostap-mykhaylyak/kavira/internal/bootstrap"
	"github.com/ostap-mykhaylyak/kavira/internal/checks"
	"github.com/ostap-mykhaylyak/kavira/internal/config"
	"github.com/ostap-mykhaylyak/kavira/internal/container"
	"github.com/ostap-mykhaylyak/kavira/internal/dkim"
	"github.com/ostap-mykhaylyak/kavira/internal/imap"
	"github.com/ostap-mykhaylyak/kavira/internal/logging"
	"github.com/ostap-mykhaylyak/kavira/internal/mailauth"
	"github.com/ostap-mykhaylyak/kavira/internal/maildir"
	"github.com/ostap-mykhaylyak/kavira/internal/paths"
	"github.com/ostap-mykhaylyak/kavira/internal/pop3"
	"github.com/ostap-mykhaylyak/kavira/internal/proc"
	"github.com/ostap-mykhaylyak/kavira/internal/queue"
	"github.com/ostap-mykhaylyak/kavira/internal/ratelimit"
	"github.com/ostap-mykhaylyak/kavira/internal/reputation"
	"github.com/ostap-mykhaylyak/kavira/internal/smtp"
	"github.com/ostap-mykhaylyak/kavira/internal/storage"
	ktls "github.com/ostap-mykhaylyak/kavira/internal/tls"
)

// version is injected at build time via -ldflags "-X main.version=...".
var version = "dev"

// certRefreshInterval bounds how stale an on-disk renewed certificate
// can stay unloaded without a SIGHUP: certbot renews in place, kavira
// re-reads on this interval and on every reload.
const certRefreshInterval = 12 * time.Hour

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}

	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "start":
		fs := flag.NewFlagSet("start", flag.ExitOnError)
		cfgPath := fs.String("config", paths.ConfigFile, "config file")
		pidfile := fs.String("pidfile", paths.Pidfile, "pidfile path")
		fs.Parse(args)
		fatalIf(runDaemon(*cfgPath, *pidfile))

	case "stop":
		fs := flag.NewFlagSet("stop", flag.ExitOnError)
		pidfile := fs.String("pidfile", paths.Pidfile, "pidfile path")
		fs.Parse(args)
		fatalIf(proc.Stop(*pidfile))

	case "reload":
		fs := flag.NewFlagSet("reload", flag.ExitOnError)
		pidfile := fs.String("pidfile", paths.Pidfile, "pidfile path")
		fs.Parse(args)
		fatalIf(proc.Reload(*pidfile))

	case "check-config":
		fs := flag.NewFlagSet("check-config", flag.ExitOnError)
		cfgPath := fs.String("config", paths.ConfigFile, "config file")
		fs.Parse(args)
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "config error:", err)
			os.Exit(1)
		}
		for _, w := range cfg.Warnings {
			fmt.Println("warning:", w)
		}
		fmt.Printf("%s: config OK\n", *cfgPath)
		fmt.Printf("domains: %d from %s\n", len(cfg.Domains), cfg.DomainsDir)
		for _, d := range cfg.Domains {
			n := 0
			for _, u := range cfg.Users {
				if strings.HasSuffix(u.Email, "@"+d.Name) {
					n++
				}
			}
			storage := d.Storage.Type
			if storage == "" {
				storage = config.StorageVirtual
			}
			fmt.Printf("  %-30s %-12s %d mailbox(es)\n", d.Name, storage, n)
		}

	// Both spellings are accepted: kavira uses subcommands, but the
	// lifecycle flags read naturally as flags too.
	case "init", "--init":
		fatalIf(bootstrap.Init(version, os.Stdout))

	case "purge", "--purge":
		fs := flag.NewFlagSet("purge", flag.ExitOnError)
		assumeYes := fs.Bool("yes", false, "skip the confirmation prompt")
		fs.Parse(args)
		fatalIf(bootstrap.Purge(*assumeYes, os.Stdin, os.Stdout))

	case "version", "--version":
		fmt.Println("kavira", version)

	case "hash-password":
		// Read from stdin (not argv: passwords must not land in the
		// shell history or the process list).
		fmt.Fprint(os.Stderr, "password: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			fatalIf(err)
		}
		pw := strings.TrimRight(line, "\r\n")
		if pw == "" {
			fatalIf(fmt.Errorf("empty password"))
		}
		h, err := auth.HashArgon2id(pw)
		fatalIf(err)
		fmt.Println(h)

	case "generate-dkim":
		fs := flag.NewFlagSet("generate-dkim", flag.ExitOnError)
		selector := fs.String("selector", dkim.DefaultSelector, "DKIM selector")
		dir := fs.String("dir", paths.DKIMDir, "key directory")
		fs.Parse(args)
		if fs.NArg() != 1 {
			fatalIf(fmt.Errorf("usage: kavira generate-dkim [--selector s] [--dir d] <domain>"))
		}
		domain := strings.ToLower(fs.Arg(0))
		name, value, err := dkim.Generate(*dir, domain, *selector)
		if err != nil {
			// An existing key is re-displayed, not overwritten.
			if n, v, terr := dkim.NewStore(*dir).TXTRecord(domain, *selector); terr == nil {
				fmt.Fprintln(os.Stderr, "kavira:", err)
				fmt.Printf("\nExisting DNS record:\n\n%s. IN TXT %q\n", n, v)
				return
			}
			fatalIf(err)
		}
		fmt.Printf("DKIM key generated for %s (selector %s).\n\nPublish this DNS record:\n\n%s. IN TXT %q\n",
			domain, *selector, name, value)

	case "security-check", "audit", "container-check":
		fs := flag.NewFlagSet(cmd, flag.ExitOnError)
		cfgPath := fs.String("config", paths.ConfigFile, "config file")
		probeHost := fs.String("host", "", "address to probe instead of server.hostname (security-check)")
		fs.Parse(args)

		cfg, err := config.Load(*cfgPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "config error:", err)
			os.Exit(1)
		}
		var report *checks.Report
		var title string
		switch cmd {
		case "security-check":
			report, title = checks.SecurityCheck(cfg, *probeHost), "kavira security check"
		case "audit":
			report, title = checks.Audit(cfg, *cfgPath), "kavira configuration audit"
		default:
			report, title = checks.ContainerCheck(cfg), "kavira container check"
		}
		report.Print(os.Stdout, title)
		os.Exit(report.ExitCode())

	default:
		fmt.Fprintf(os.Stderr, "kavira: unknown command %q\n\n", cmd)
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w *os.File) {
	fmt.Fprint(w, `kavira - enterprise secure mail server

Setup:
  init           create the filesystem layout, default config and unit
  purge          remove config, domains, logs and state (asks first)

Commands:
  start          run the daemon in the foreground (what systemd does)
  stop           signal the running daemon to shut down
  reload         signal the running daemon to reload config and certs
  check-config   validate the configuration and exit
  hash-password  read a password from stdin, print its argon2id hash
  version        print version and exit

  generate-dkim  create a domain's DKIM key, print the DNS record

Diagnostics (exit 1 when a check fails):
  audit           inspect the local configuration and filesystem, no network
  security-check  probe the live deployment: relay, TLS, DNS, rDNS, blacklists
  container-check verify the public identity of a containerized deployment
`)
}

func notYet(cmd, milestone string) {
	fmt.Fprintf(os.Stderr, "kavira %s: not implemented yet (planned for milestone %s)\n", cmd, milestone)
	os.Exit(2)
}

func fatalIf(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "kavira:", err)
		os.Exit(1)
	}
}

func runDaemon(cfgPath, pidfile string) (err error) {
	// First execution without a config: auto-provision the default
	// layout from the embedded skel, warn on stderr and keep going.
	if cfgPath == paths.ConfigFile {
		if _, statErr := os.Stat(cfgPath); os.IsNotExist(statErr) {
			fmt.Fprintln(os.Stderr, "kavira: no config found, provisioning default layout")
			if err := bootstrap.EnsureLayout(os.Stderr); err != nil {
				return err
			}
		}
	}

	mgr, err := config.NewManager(cfgPath)
	if err != nil {
		return err
	}
	cfg := mgr.Get()

	logs, err := logging.Open(cfg.Log.Dir)
	if err != nil {
		return err
	}
	defer logs.Close()
	// Surface a fatal startup error in the service log too, not only
	// on stderr — otherwise a crash loop is invisible to anyone
	// reading kavira.log. Runs before logs.Close.
	defer func() {
		if err != nil {
			logs.Service.Error("fatal error, exiting", "error", err.Error())
		}
	}()

	logs.Service.Info("starting", "version", version, "config", cfgPath, "pid", os.Getpid())
	for _, w := range cfg.Warnings {
		logs.Service.Warn("config warning", "warning", w)
	}

	// Public identity: nothing kavira writes may carry the container's
	// own name, including the host part of Maildir filenames.
	maildir.SetHostname(cfg.Server.Hostname)
	if leaks, why := container.LeaksContainerName(cfg.Server.Hostname); leaks {
		logs.Service.Warn("server.hostname is not a public mail hostname",
			"hostname", cfg.Server.Hostname, "reason", why)
	}
	if rt := container.Detect(); rt != container.RuntimeNone {
		logs.Service.Info("container runtime detected",
			"runtime", string(rt), "container_mode", cfg.Container.Enabled)
		if !cfg.Container.Enabled {
			logs.Service.Warn("running in a container without container mode: internal addresses may reach outgoing mail",
				"runtime", string(rt))
		}
	}

	if err := proc.WritePidfile(pidfile); err != nil {
		// Not fatal: under systemd the MAINPID is known anyway, and in
		// development /run may not exist.
		logs.Service.Warn("pidfile not written", "path", pidfile, "error", err.Error())
	} else {
		defer proc.RemovePidfile(pidfile)
	}

	store, warns := ktls.New(tlsParams(cfg))
	for _, w := range warns {
		logs.Service.Warn("tls warning", "warning", w)
	}
	logs.Service.Info("tls certificates loaded",
		"domains", store.Loaded(), "min_version", cfg.TLS.MinVersion)

	// --- authentication (survives reloads: lookup reads mgr.Get()) ---
	authr := auth.New(
		func(email string) (string, bool) { return mgr.Get().PasswordHashFor(email) },
		cfg.Auth.MaxFailures, time.Duration(cfg.Auth.LockoutMinutes)*time.Minute)

	dkimStore := dkim.NewStore(cfg.DKIM.Dir)

	// --- blacklists (DNSBL for IPs, URIBL for body links) ---
	var bl *blacklist.Checker
	if cfg.Blacklist.IsEnabled() {
		bl = blacklist.New(cfg.Blacklist.DNSBL, cfg.Blacklist.URIBL,
			time.Duration(cfg.Blacklist.CacheMinutes)*time.Minute)
		logs.Service.Info("blacklists enabled",
			"dnsbl", len(cfg.Blacklist.DNSBL), "uribl", len(cfg.Blacklist.URIBL),
			"reject_listed", cfg.Blacklist.RejectListed)
	}

	// --- antivirus ---
	var scanner antispam.Scanner
	if cfg.Antivirus.Enabled {
		av := antivirus.New(cfg.Antivirus.Socket,
			time.Duration(cfg.Antivirus.TimeoutSeconds)*time.Second)
		if err := av.Ping(); err != nil {
			// Not fatal: clamd may still be starting. Scans will
			// error until it answers, and reject_on_error decides
			// what that means for the mail.
			logs.Service.Warn("clamav not reachable at startup",
				"socket", cfg.Antivirus.Socket, "error", err.Error())
		} else {
			logs.Service.Info("antivirus enabled", "socket", cfg.Antivirus.Socket)
		}
		scanner = av
	}

	// --- antispam ---
	var spamEngine *antispam.Engine
	var bayes *antispam.Bayes
	if cfg.Antispam.IsEnabled() {
		var err error
		bayes, err = antispam.NewBayes(cfg.Antispam.BayesFile)
		if err != nil {
			logs.Service.Warn("bayes corpus not loaded, starting empty",
				"file", cfg.Antispam.BayesFile, "error", err.Error())
			bayes, _ = antispam.NewBayes("")
		}
		spamEngine = &antispam.Engine{Bayes: bayes, Scanner: scanner}
		if bl != nil {
			spamEngine.URIBL = bl
		}
		ham, spam := bayes.Trained()
		logs.Service.Info("antispam enabled",
			"bayes_ham", ham, "bayes_spam", spam, "bayes_ready", bayes.Ready(),
			"tag", cfg.Antispam.TagScore, "quarantine", cfg.Antispam.QuarantineScore,
			"reject", cfg.Antispam.RejectScore)
	}

	// --- reputation ---
	var rep *reputation.Store
	if cfg.Reputation.IsEnabled() {
		var err error
		rep, err = reputation.Open(cfg.Reputation.File)
		if err != nil {
			logs.Service.Warn("reputation store not loaded, starting empty",
				"file", cfg.Reputation.File, "error", err.Error())
			rep, _ = reputation.Open("")
		}
		logs.Service.Info("reputation enabled",
			"file", cfg.Reputation.File, "warmup", cfg.Reputation.WarmUp.Enabled)
	}
	warmUp := func(cfg *config.Config) reputation.WarmUp {
		w := cfg.Reputation.WarmUp
		return reputation.WarmUp{Enabled: w.Enabled, Day1: w.Day1, Day7: w.Day7, Full: w.FullPerDay}
	}

	// --- outbound queue + scheduler ---
	q, err := queue.Open(cfg.Queue.Dir)
	if err != nil {
		return err
	}
	transport := &queue.SMTPTransport{Hostname: cfg.Server.Hostname}
	bounceFn := func(e *queue.Envelope, reason string) {
		// A hard bounce is reputation-relevant: it is the clearest
		// signal that a sender is mailing addresses it should not.
		if rep != nil && e.From != "" {
			rep.Record("user:"+e.From, reputation.EventBounce)
			if _, domain, ok := storage.Split(e.From); ok {
				rep.Record("domain:"+domain, reputation.EventBounce)
			}
		}
		data := queue.BuildBounce(mgr.Get().Server.Hostname, e, reason)
		if data == nil {
			return // null reverse-path: never bounce a bounce
		}
		mb, ok := storage.Resolve(mgr.Get(), e.From)
		if !ok {
			logs.Service.Warn("bounce dropped: sender not local",
				"event", "bounce_dropped", "queue_id", e.ID, "from", e.From)
			return
		}
		full := append([]byte("Return-Path: <>\r\n"), data...)
		if _, err := maildir.Deliver(mb.Dir, full, mb.UID, mb.GID); err != nil {
			logs.Service.Error("bounce delivery failed",
				"queue_id", e.ID, "from", e.From, "error", err.Error())
		}
	}
	sched := queue.NewScheduler(q, transport, bounceFn, cfg.Queue.MaxAttempts, logs.Service)
	schedStop := make(chan struct{})
	go sched.Run(schedStop)
	logs.Service.Info("outbound queue open", "dir", cfg.Queue.Dir, "pending", q.Size())

	// --- state persistence: the learned corpus and the scores are
	// flushed periodically and on shutdown, so a crash loses at most
	// one interval of learning rather than everything. ---
	stateStop := make(chan struct{})
	saveState := func() {
		if bayes != nil {
			if err := bayes.Save(); err != nil {
				logs.Service.Error("bayes save failed", "error", err.Error())
			}
		}
		if rep != nil {
			if err := rep.Save(); err != nil {
				logs.Service.Error("reputation save failed", "error", err.Error())
			}
		}
	}
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-stateStop:
				return
			case <-t.C:
				saveState()
			}
		}
	}()

	backend := smtp.Backend{
		IsLocalDomain: func(d string) bool { return mgr.Get().HasDomain(d) },
		Lookup: func(email string) (storage.Mailbox, bool) {
			return storage.Resolve(mgr.Get(), email)
		},
		Deliver: func(mb storage.Mailbox, from string, spam bool, msg []byte) error {
			dir := mb.Dir
			if spam {
				dir = filepath.Join(dir, ".Spam") // Maildir++ quarantine
			}
			full := append([]byte("Return-Path: <"+from+">\r\n"), msg...)
			_, err := maildir.Deliver(dir, full, mb.UID, mb.GID)
			return err
		},
		Postmaster: func() string {
			if doms := mgr.Get().Domains; len(doms) > 0 {
				return "postmaster@" + doms[0].Name
			}
			return ""
		},
		Authenticate: authr.Verify,
		Enqueue:      q.Enqueue,
		Screen: func(ip, helo, from string, data []byte) smtp.ScreenResult {
			cfg := mgr.Get()
			var out smtp.ScreenResult

			// --- SPF / DKIM / DMARC ---
			if cfg.MailAuth.IsEnabled() {
				checker := mailauth.New(cfg.Server.Hostname, cfg.MailAuth.IsEnforced())
				res := checker.Check(net.ParseIP(ip), helo, from, data)
				logs.Service.Info("mail authentication",
					"event", "mail_auth", "protocol", "smtp", "ip", ip, "from", from,
					"spf", res.SPF, "dkim", res.DKIM, "dmarc", res.DMARC)
				out.AuthResults = res.AuthResults
				out.Reason = res.Reason
				switch res.Action {
				case mailauth.Reject:
					out.Action = smtp.ScreenReject
					return out // a DMARC reject settles it, no need to score
				case mailauth.Quarantine:
					out.Action = smtp.ScreenQuarantine
				}
			}

			// --- DNSBL on the connecting IP ---
			if bl != nil && cfg.Blacklist.RejectListed {
				if listed, zones := bl.ListedIP(ip); listed {
					logs.Service.Warn("connection from blacklisted ip",
						"event", "blacklist_hit", "protocol", "smtp", "ip", ip,
						"zones", zones, "action", "reject")
					out.Action = smtp.ScreenReject
					out.Reason = fmt.Sprintf("your IP is listed on %s", strings.Join(zones, ", "))
					return out
				}
			}

			// --- antispam scoring ---
			if spamEngine != nil {
				v := spamEngine.Check(data)
				out.SpamHeader = v.Header(cfg.Antispam.TagScore)
				logs.Service.Info("message scored",
					"event", "spam_score", "protocol", "smtp", "ip", ip, "from", from,
					"score", v.Score, "bayes", v.Bayes, "rules", v.Rules, "virus", v.Virus)

				switch {
				case v.Virus != "":
					// Malware is never delivered, not even quarantined.
					out.Action = smtp.ScreenReject
					out.Reason = fmt.Sprintf("message contains %s", v.Virus)
					return out
				case v.BadAttachment != "" && cfg.Antispam.RejectsExecutables():
					out.Action = smtp.ScreenReject
					out.Reason = fmt.Sprintf("executable attachment refused: %s", v.BadAttachment)
					return out
				case v.Score >= cfg.Antispam.RejectScore:
					out.Action = smtp.ScreenReject
					out.Reason = fmt.Sprintf("message rejected, spam score %.1f", v.Score)
					return out
				case v.Score >= cfg.Antispam.QuarantineScore:
					out.Action = smtp.ScreenQuarantine
					if out.Reason == "" {
						out.Reason = fmt.Sprintf("spam score %.1f", v.Score)
					}
				}
			}
			return out
		},
		MaySend: func(user, domain string) (bool, string) {
			if rep == nil {
				return true, ""
			}
			if rep.Blocked("user:" + user) {
				return false, "sending temporarily suspended, contact your administrator"
			}
			if rep.Blocked("domain:" + domain) {
				return false, "domain sending temporarily suspended"
			}
			if ok, limit := rep.AllowSend("domain:"+domain, warmUp(mgr.Get())); !ok {
				return false, fmt.Sprintf("daily sending limit reached (%d), try again tomorrow", limit)
			}
			return true, ""
		},
		Sent: func(user, domain string) {
			if rep == nil {
				return
			}
			rep.Record("user:"+user, reputation.EventDelivered)
			rep.Record("domain:"+domain, reputation.EventDelivered)
		},
		Sign: func(fromDomain string, msg []byte) ([]byte, error) {
			cfg := mgr.Get()
			sel := cfg.DKIMSelectorFor(fromDomain)
			signer, ok := dkimStore.Signer(fromDomain, sel)
			if !ok {
				return msg, nil // no key: send unsigned
			}
			return dkim.Sign(msg, fromDomain, sel, signer)
		},
	}

	// --- listeners: 25 inbound, 587 submission, 465 submission TLS ---
	limits := newLimits(cfg)
	specs := []struct {
		name     string
		addr     string
		mode     smtp.Mode
		implicit bool
	}{
		{"smtp", cfg.Listeners.SMTP.Address, smtp.ModeInbound, false},
		{"submission", cfg.Listeners.Submission.Address, smtp.ModeSubmission, false},
		{"smtps", cfg.Listeners.SMTPS.Address, smtp.ModeSubmission, true},
	}
	type running struct {
		srv      *smtp.Server
		mode     smtp.Mode
		implicit bool
	}
	var servers []running
	for _, sp := range specs {
		if sp.addr == "" {
			continue
		}
		if sp.mode == smtp.ModeSubmission && len(store.Loaded()) == 0 {
			// Secure by default: submission without TLS would expose
			// credentials, better no listener than a plaintext one.
			logs.Service.Warn("submission listener disabled: no TLS certificate loaded",
				"protocol", sp.name, "address", sp.addr)
			continue
		}
		ln, err := net.Listen("tcp", sp.addr)
		if err != nil {
			return fmt.Errorf("%s listener %s: %w", sp.name, sp.addr, err)
		}
		if sp.implicit {
			ln = stdtls.NewListener(ln, store.Config())
		}
		srv := smtp.New(smtpSettings(cfg, store, sp.mode, sp.implicit, limits), backend, cfg.Server.Workers, logs.Service)
		go func(name string) {
			if err := srv.Serve(ln); err != nil {
				logs.Service.Error("smtp server failed", "protocol", name, "error", err.Error())
			}
		}(sp.name)
		servers = append(servers, running{srv, sp.mode, sp.implicit})
		logs.Service.Info("listening", "protocol", sp.name, "address", sp.addr, "mode", int(sp.mode))
	}
	// --- mail access: IMAP (143/993) and POP3 (110/995) ---
	// Access protocols authenticate the same accounts as submission
	// and resolve the mailbox through the same storage rules.
	accessAuth := func(email, password, ip string) (string, error) {
		if err := authr.Verify(email, password, ip); err != nil {
			return "", err
		}
		mb, ok := storage.Resolve(mgr.Get(), strings.ToLower(email))
		if !ok {
			return "", fmt.Errorf("no mailbox for %s", email)
		}
		return mb.Dir, nil
	}

	var imapServers []struct {
		srv      *imap.Server
		implicit bool
	}
	for _, sp := range []struct {
		name     string
		addr     string
		implicit bool
	}{
		{"imap", cfg.Listeners.IMAP.Address, false},
		{"imaps", cfg.Listeners.IMAPS.Address, true},
	} {
		if sp.addr == "" {
			continue
		}
		if len(store.Loaded()) == 0 {
			// Same rule as submission: no certificate, no mail access
			// listener — credentials must never cross in the clear.
			logs.Service.Warn("imap listener disabled: no TLS certificate loaded",
				"protocol", sp.name, "address", sp.addr)
			continue
		}
		ln, err := net.Listen("tcp", sp.addr)
		if err != nil {
			return fmt.Errorf("%s listener %s: %w", sp.name, sp.addr, err)
		}
		if sp.implicit {
			ln = stdtls.NewListener(ln, store.Config())
		}
		srv := imap.New(imapSettings(cfg, store, sp.implicit),
			imap.Backend{Authenticate: accessAuth}, cfg.Server.Workers, logs.Service)
		go func(name string) {
			if err := srv.Serve(ln); err != nil {
				logs.Service.Error("imap server failed", "protocol", name, "error", err.Error())
			}
		}(sp.name)
		imapServers = append(imapServers, struct {
			srv      *imap.Server
			implicit bool
		}{srv, sp.implicit})
		logs.Service.Info("listening", "protocol", sp.name, "address", sp.addr)
	}

	var pop3Servers []struct {
		srv      *pop3.Server
		implicit bool
	}
	for _, sp := range []struct {
		name     string
		addr     string
		implicit bool
	}{
		{"pop3", cfg.Listeners.POP3.Address, false},
		{"pop3s", cfg.Listeners.POP3S.Address, true},
	} {
		if sp.addr == "" {
			continue
		}
		if len(store.Loaded()) == 0 {
			logs.Service.Warn("pop3 listener disabled: no TLS certificate loaded",
				"protocol", sp.name, "address", sp.addr)
			continue
		}
		ln, err := net.Listen("tcp", sp.addr)
		if err != nil {
			return fmt.Errorf("%s listener %s: %w", sp.name, sp.addr, err)
		}
		if sp.implicit {
			ln = stdtls.NewListener(ln, store.Config())
		}
		srv := pop3.New(pop3Settings(cfg, store, sp.implicit),
			pop3.Backend{Authenticate: accessAuth}, cfg.Server.Workers, logs.Service)
		go func(name string) {
			if err := srv.Serve(ln); err != nil {
				logs.Service.Error("pop3 server failed", "protocol", name, "error", err.Error())
			}
		}(sp.name)
		pop3Servers = append(pop3Servers, struct {
			srv      *pop3.Server
			implicit bool
		}{srv, sp.implicit})
		logs.Service.Info("listening", "protocol", sp.name, "address", sp.addr)
	}

	// --- administrative API (HTTPS, static API keys only) ---
	var apiSrv *api.Server
	if cfg.API.Enabled {
		if len(store.Loaded()) == 0 {
			// The API carries credentials and mutates state: it never
			// runs unencrypted.
			logs.Service.Warn("api disabled: no TLS certificate loaded", "address", cfg.API.Address)
		} else {
			apiSrv = api.New(cfg.API.Address, cfg.API.Keys, api.Deps{
				Config:     mgr.Get,
				Reload:     mgr.Reload,
				QueueSize:  q.Size,
				Reputation: rep,
				Version:    version,
				Started:    time.Now(),
			}, logs.Service)
			ln, err := net.Listen("tcp", cfg.API.Address)
			if err != nil {
				return fmt.Errorf("api listener %s: %w", cfg.API.Address, err)
			}
			go func() {
				if err := apiSrv.Serve(stdtls.NewListener(ln, store.Config())); err != nil {
					logs.Service.Error("api server failed", "error", err.Error())
				}
			}()
			logs.Service.Info("listening", "protocol", "api", "address", cfg.API.Address,
				"keys", len(cfg.API.Keys))
		}
	}

	updateAll := func(cfg *config.Config, lim limitSet) {
		for _, r := range servers {
			r.srv.Update(smtpSettings(cfg, store, r.mode, r.implicit, lim))
		}
		for _, r := range imapServers {
			r.srv.Update(imapSettings(cfg, store, r.implicit))
		}
		for _, r := range pop3Servers {
			r.srv.Update(pop3Settings(cfg, store, r.implicit))
		}
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP, syscall.SIGTERM, os.Interrupt)
	refresh := time.NewTicker(certRefreshInterval)
	defer refresh.Stop()

	logs.Service.Info("ready", "hostname", cfg.Server.Hostname)
	for {
		select {
		case <-refresh.C:
			for _, w := range store.Reload(tlsParams(mgr.Get())) {
				logs.Service.Warn("tls warning", "warning", w)
			}
			// A certificate may have appeared on a fresh install:
			// re-evaluate the STARTTLS offer. Limiters are kept, so
			// quotas are not reset by the periodic refresh.
			updateAll(mgr.Get(), limits)

		case s := <-sigs:
			switch s {
			case syscall.SIGHUP:
				logs.Service.Info("reload requested")
				if err := logs.Reopen(); err != nil {
					logs.Service.Error("log reopen failed", "error", err.Error())
				}
				if err := mgr.Reload(); err != nil {
					logs.Service.Error("config reload failed, keeping previous config", "error", err.Error())
					continue
				}
				cfg := mgr.Get()
				for _, w := range cfg.Warnings {
					logs.Service.Warn("config warning", "warning", w)
				}
				for _, w := range store.Reload(tlsParams(cfg)) {
					logs.Service.Warn("tls warning", "warning", w)
				}
				limits = newLimits(cfg)
				updateAll(cfg, limits)
				logs.Service.Info("reload complete",
					"domains", len(cfg.Domains), "tls_loaded", store.Loaded())

			default: // SIGTERM, Interrupt
				logs.Service.Info("shutdown requested", "signal", s.String())
				close(schedStop)
				close(stateStop)
				saveState()
				if apiSrv != nil {
					apiSrv.Shutdown(5 * time.Second)
				}
				for _, r := range servers {
					r.srv.Shutdown(30 * time.Second)
				}
				for _, r := range imapServers {
					r.srv.Shutdown(30 * time.Second)
				}
				for _, r := range pop3Servers {
					r.srv.Shutdown(30 * time.Second)
				}
				logs.Service.Info("stopped", "queued", q.Size())
				return nil
			}
		}
	}
}

// limitSet holds the shared limiter instances: they live across
// settings updates so quotas are not reset by a periodic refresh.
type limitSet struct {
	in  *ratelimit.Inbound
	out *ratelimit.Outbound
}

// newLimits builds the limiters from the current config (fresh
// instances on SIGHUP reload, since the rates may have changed).
func newLimits(cfg *config.Config) limitSet {
	var l limitSet
	if in := cfg.RateLimit.Inbound; in.IsEnabled() {
		l.in = ratelimit.NewInbound(
			in.IP.ConnectionsPerMinute, in.IP.MessagesPerMinute, in.IP.RecipientsPerMinute)
	}
	if out := cfg.RateLimit.Outbound; out.IsEnabled() {
		l.out = ratelimit.NewOutbound(out.User.MessagesPerHour, out.User.RecipientsPerHour)
	}
	return l
}

// smtpSettings maps the current config onto one SMTP listener.
// STARTTLS is offered only when at least one certificate actually
// loaded.
func smtpSettings(cfg *config.Config, store *ktls.Store, mode smtp.Mode, implicit bool, lim limitSet) smtp.Settings {
	set := smtp.Settings{
		Hostname:      cfg.Server.Hostname,
		MaxSize:       cfg.SMTP.MaxSize,
		MaxRecipients: cfg.SMTP.MaxRecipients,
		Mode:          mode,
		ImplicitTLS:   implicit,
		Limits:        lim.in,
		OutLimits:     lim.out,
		Identity: container.Identity{
			Enabled:    cfg.Container.Enabled,
			Hostname:   cfg.Server.Hostname,
			PublicIP:   cfg.Container.PublicIP,
			InternalIP: cfg.Container.InternalIP,
		},
	}
	if !implicit && len(store.Loaded()) > 0 {
		set.TLS = store.Config()
	}
	return set
}

// imapSettings maps the config onto one IMAP listener.
func imapSettings(cfg *config.Config, store *ktls.Store, implicit bool) imap.Settings {
	set := imap.Settings{
		Hostname:    cfg.Server.Hostname,
		ImplicitTLS: implicit,
		MaxSize:     cfg.SMTP.MaxSize,
	}
	if !implicit && len(store.Loaded()) > 0 {
		set.TLS = store.Config()
	}
	return set
}

// pop3Settings maps the config onto one POP3 listener.
func pop3Settings(cfg *config.Config, store *ktls.Store, implicit bool) pop3.Settings {
	set := pop3.Settings{
		Hostname:    cfg.Server.Hostname,
		ImplicitTLS: implicit,
	}
	if !implicit && len(store.Loaded()) > 0 {
		set.TLS = store.Config()
	}
	return set
}

func tlsParams(cfg *config.Config) ktls.Params {
	return ktls.Params{
		CertRoot:       cfg.TLS.CertRoot,
		Hostname:       cfg.Server.Hostname,
		Domains:        cfg.DomainNames(),
		MinVersion:     cfg.TLS.MinVersion,
		ExpiryWarnDays: cfg.TLS.ExpiryWarnDays,
	}
}
