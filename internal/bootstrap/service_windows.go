//go:build windows

package bootstrap

import "io"

// stopService is a no-op: init and purge are Linux-only.
func stopService(w io.Writer) {}
