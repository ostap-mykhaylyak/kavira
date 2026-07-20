// Package bootstrap provisions and removes kavira's filesystem
// layout: the configuration directory with its per-domain files, the
// state and log directories, and the systemd unit.
package bootstrap

import (
	"bufio"
	_ "embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ostap-mykhaylyak/kavira/internal/paths"
)

//go:embed skel/etc/kavira/config.yaml
var defaultConfig []byte

//go:embed skel/etc/kavira/domains/example.com.yaml
var exampleDomain []byte

//go:embed kavira.service
var Unit []byte

// unitPath is where the systemd unit is installed.
const unitPath = "/etc/systemd/system/kavira.service"

// dir describes one directory of the layout.
type dir struct {
	path string
	mode os.FileMode
}

// layout is every directory kavira owns, with the mode it must have.
// The DKIM directory is the strictest: its private keys are the one
// secret whose leak lets anyone sign as the domain.
func layout() []dir {
	return []dir{
		{paths.ConfigDir, 0o750},
		{paths.DomainsDir, 0o750},
		{paths.LogDir, 0o750},
		{paths.StateDir, 0o750},
		{paths.QueueDir, 0o750},
		{paths.DKIMDir, 0o700},
	}
}

// EnsureLayout creates the standard directories and, if absent, the
// default configuration. Progress goes to w.
func EnsureLayout(w io.Writer) error {
	if runtime.GOOS == "windows" {
		return fmt.Errorf("the default layout is Linux-only; pass --config")
	}
	for _, d := range layout() {
		if err := os.MkdirAll(d.path, d.mode); err != nil {
			return err
		}
		// MkdirAll applies the umask, so set the mode explicitly.
		if err := os.Chmod(d.path, d.mode); err != nil {
			return err
		}
	}
	if _, err := os.Stat(paths.ConfigFile); os.IsNotExist(err) {
		if err := os.WriteFile(paths.ConfigFile, defaultConfig, 0o640); err != nil {
			return err
		}
		fmt.Fprintf(w, "kavira: wrote default config to %s\n", paths.ConfigFile)
	}
	return nil
}

// Init provisions the full layout, an example domain file and the
// systemd unit, then prints what to do next. It never overwrites an
// existing file: running it twice is safe.
func Init(version string, w io.Writer) error {
	if runtime.GOOS == "windows" {
		return fmt.Errorf("kavira init is Linux-only")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("kavira init must run as root (it writes to %s and %s)",
			paths.ConfigDir, paths.StateDir)
	}

	for _, d := range layout() {
		created := false
		if _, err := os.Stat(d.path); os.IsNotExist(err) {
			created = true
		}
		if err := os.MkdirAll(d.path, d.mode); err != nil {
			return err
		}
		if err := os.Chmod(d.path, d.mode); err != nil {
			return err
		}
		if created {
			fmt.Fprintf(w, "created %s (mode %04o)\n", d.path, d.mode)
		}
	}

	// Install the running executable, so the binary unpacked from the
	// release tarball becomes the one systemd starts. Without this,
	// `./kavira init` would provision a service pointing at a path
	// that holds nothing.
	if err := installSelf(w); err != nil {
		return err
	}

	if err := writeIfAbsent(w, paths.ConfigFile, defaultConfig, 0o640); err != nil {
		return err
	}
	examplePath := filepath.Join(paths.DomainsDir, "example.com.yaml.example")
	if err := writeIfAbsent(w, examplePath, exampleDomain, 0o640); err != nil {
		return err
	}
	if err := writeIfAbsent(w, unitPath, Unit, 0o644); err != nil {
		return err
	}

	fmt.Fprintf(w, `
kavira %s is provisioned. Next:

  1. edit %s
       set server.hostname to the public name of this server

  2. create your first domain
       cp %s %s/example.com.yaml
       edit it: the file name is the domain name

  3. add a mailbox password
       kavira hash-password

  4. obtain a wildcard certificate into %s/<domain>/

  5. check and start
       kavira check-config
       systemctl daemon-reload
       systemctl enable --now kavira
       kavira status

  6. verify the deployment
       kavira audit
       kavira security-check
`, version, paths.ConfigFile, examplePath, paths.DomainsDir, "/etc/letsencrypt/live")
	return nil
}

// installSelf copies the running executable to paths.Binary, unless
// it is already running from there. Unlike the configuration, this is
// overwritten: re-running init from a newer tarball is how an upgrade
// is performed.
func installSelf(w io.Writer) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locating the running binary: %w", err)
	}
	if self, err = filepath.EvalSymlinks(self); err != nil {
		return fmt.Errorf("locating the running binary: %w", err)
	}
	if self == paths.Binary {
		return nil // already installed, nothing to copy
	}

	src, err := os.Open(self)
	if err != nil {
		return fmt.Errorf("reading %s: %w", self, err)
	}
	defer src.Close()

	// Write to a temporary file and rename: replacing a running
	// binary in place fails with ETXTBSY, and a partial copy would
	// leave an unstartable service.
	tmp := paths.Binary + ".new"
	dst, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("writing %s: %w", tmp, err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		os.Remove(tmp)
		return fmt.Errorf("writing %s: %w", tmp, err)
	}
	if err := dst.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, paths.Binary); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("installing %s: %w", paths.Binary, err)
	}
	fmt.Fprintf(w, "installed %s\n", paths.Binary)
	return nil
}

// writeIfAbsent writes data unless the file already exists, so an
// operator's edits are never destroyed by a second init.
func writeIfAbsent(w io.Writer, path string, data []byte, mode os.FileMode) error {
	if _, err := os.Stat(path); err == nil {
		fmt.Fprintf(w, "kept %s (already exists)\n", path)
		return nil
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		return err
	}
	fmt.Fprintf(w, "wrote %s\n", path)
	return nil
}

// Purge removes everything kavira owns: configuration, domains, logs,
// state (queue, DKIM keys, learned corpus, reputation) and the unit.
//
// This destroys the DKIM private keys and every queued message, and
// neither can be recovered — which is why it asks first, lists what it
// is about to delete, and requires the confirmation to be typed in
// full rather than accepting a bare "y".
func Purge(assumeYes bool, in io.Reader, w io.Writer) error {
	if runtime.GOOS == "windows" {
		return fmt.Errorf("kavira purge is Linux-only")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("kavira purge must run as root")
	}

	targets := []string{
		paths.ConfigDir, // includes domains/
		paths.LogDir,
		paths.StateDir, // includes queue/, dkim/, bayes, reputation
		unitPath,
	}
	var present []string
	for _, t := range targets {
		if _, err := os.Stat(t); err == nil {
			present = append(present, t)
		}
	}
	if len(present) == 0 {
		fmt.Fprintln(w, "nothing to remove")
		return nil
	}

	fmt.Fprintln(w, "This will permanently delete:")
	for _, p := range present {
		fmt.Fprintf(w, "  %s\n", p)
	}
	fmt.Fprintln(w, "\nIncluding the DKIM private keys, the outbound queue and every")
	fmt.Fprintln(w, "learned spam corpus. Mailboxes outside these paths are NOT removed.")

	if !assumeYes {
		fmt.Fprint(w, "\nType 'purge kavira' to confirm: ")
		line, _ := bufio.NewReader(in).ReadString('\n')
		if strings.TrimSpace(line) != "purge kavira" {
			return fmt.Errorf("aborted")
		}
	}

	// Stop the service first: removing the queue under a running
	// daemon would leave it writing into deleted directories.
	stopService(w)

	for _, p := range present {
		if err := os.RemoveAll(p); err != nil {
			return fmt.Errorf("removing %s: %w", p, err)
		}
		fmt.Fprintf(w, "removed %s\n", p)
	}
	// The binary is removed last: it is the one running this code, so
	// the copy on disk goes only once everything else is gone.
	if _, err := os.Stat(paths.Binary); err == nil {
		if err := os.Remove(paths.Binary); err != nil {
			fmt.Fprintf(w, "note: could not remove %s: %v\n", paths.Binary, err)
		} else {
			fmt.Fprintf(w, "removed %s\n", paths.Binary)
		}
	}
	fmt.Fprintln(w, "\nkavira removed.")
	return nil
}
