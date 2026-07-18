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

	"github.com/ostap-mykhaylyak/kavira/internal/auth"
	"github.com/ostap-mykhaylyak/kavira/internal/bootstrap"
	"github.com/ostap-mykhaylyak/kavira/internal/config"
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
		fmt.Printf("%s: config OK (%d domains, %d users)\n",
			*cfgPath, len(cfg.Domains), len(cfg.Users))

	case "version":
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
		notYet(cmd, "M6")

	default:
		fmt.Fprintf(os.Stderr, "kavira: unknown command %q\n\n", cmd)
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w *os.File) {
	fmt.Fprint(w, `kavira - enterprise secure mail server

Commands:
  start          run the daemon in the foreground (what systemd does)
  stop           signal the running daemon to shut down
  reload         signal the running daemon to reload config and certs
  check-config   validate the configuration and exit
  hash-password  read a password from stdin, print its argon2id hash
  version        print version and exit

  generate-dkim  create a domain's DKIM key, print the DNS record

Planned:
  security-check audit container-check
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

	// --- outbound queue + scheduler ---
	q, err := queue.Open(cfg.Queue.Dir)
	if err != nil {
		return err
	}
	transport := &queue.SMTPTransport{Hostname: cfg.Server.Hostname}
	bounceFn := func(e *queue.Envelope, reason string) {
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

	// --- authentication (survives reloads: lookup reads mgr.Get()) ---
	authr := auth.New(
		func(email string) (string, bool) { return mgr.Get().PasswordHashFor(email) },
		cfg.Auth.MaxFailures, time.Duration(cfg.Auth.LockoutMinutes)*time.Minute)

	dkimStore := dkim.NewStore(cfg.DKIM.Dir)

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
			if !cfg.MailAuth.IsEnabled() {
				return smtp.ScreenResult{}
			}
			checker := mailauth.New(cfg.Server.Hostname, cfg.MailAuth.IsEnforced())
			res := checker.Check(net.ParseIP(ip), helo, from, data)
			logs.Service.Info("mail authentication",
				"event", "mail_auth", "protocol", "smtp", "ip", ip, "from", from,
				"spf", res.SPF, "dkim", res.DKIM, "dmarc", res.DMARC)
			out := smtp.ScreenResult{Reason: res.Reason, AuthResults: res.AuthResults}
			switch res.Action {
			case mailauth.Reject:
				out.Action = smtp.ScreenReject
			case mailauth.Quarantine:
				out.Action = smtp.ScreenQuarantine
			}
			return out
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
