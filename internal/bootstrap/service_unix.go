//go:build !windows

package bootstrap

import (
	"fmt"
	"io"
	"os/exec"
)

// stopService disables and stops the unit before a purge. Failures are
// reported but not fatal: on a machine where kavira was never enabled,
// or where systemd is absent, there is simply nothing to stop.
func stopService(w io.Writer) {
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return
	}
	for _, args := range [][]string{
		{"disable", "--now", "kavira"},
	} {
		cmd := exec.Command(systemctl, args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			fmt.Fprintf(w, "note: systemctl %v: %v\n", args, err)
			_ = out
		} else {
			fmt.Fprintln(w, "stopped and disabled the kavira service")
		}
	}
}
