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
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ostap-mykhaylyak/kavira/internal/bootstrap"
	"github.com/ostap-mykhaylyak/kavira/internal/config"
	"github.com/ostap-mykhaylyak/kavira/internal/logging"
	"github.com/ostap-mykhaylyak/kavira/internal/paths"
	"github.com/ostap-mykhaylyak/kavira/internal/proc"
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

	case "generate-dkim":
		notYet(cmd, "M3")
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
  version        print version and exit

Planned:
  generate-dkim security-check audit container-check
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

	// From M1 on the protocol listeners start here, consuming
	// store.Config() and mgr.Get() per session.

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
				logs.Service.Info("reload complete",
					"domains", len(cfg.Domains), "tls_loaded", store.Loaded())

			default: // SIGTERM, Interrupt
				logs.Service.Info("shutdown requested", "signal", s.String())
				// Graceful drain of protocol sessions lands with M1.
				logs.Service.Info("stopped")
				return nil
			}
		}
	}
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
