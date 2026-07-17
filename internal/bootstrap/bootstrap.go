// Package bootstrap provisions the default filesystem layout from the
// embedded skeleton: config directory, state and log directories, and
// a commented default configuration on first start.
package bootstrap

import (
	_ "embed"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/ostap-mykhaylyak/kavira/internal/paths"
)

//go:embed skel/etc/kavira/config.yaml
var defaultConfig []byte

//go:embed kavira.service
var Unit []byte

// EnsureLayout creates the standard directories and, if absent, the
// default config file. Progress goes to w. Linux-only paths: on other
// systems it refuses, development uses --config instead.
func EnsureLayout(w io.Writer) error {
	if runtime.GOOS == "windows" {
		return fmt.Errorf("default layout provisioning is Linux-only; pass --config")
	}
	for _, d := range []struct {
		path string
		mode os.FileMode
	}{
		{paths.ConfigDir, 0o750},
		{paths.LogDir, 0o750},
		{paths.StateDir, 0o750},
		{paths.QueueDir, 0o750},
		{paths.DKIMDir, 0o700},
	} {
		if err := os.MkdirAll(d.path, d.mode); err != nil {
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
