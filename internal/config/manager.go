package config

import "sync/atomic"

// Manager holds the current configuration behind an atomic pointer:
// Get is cheap, safe on the hot path, and callable per-session.
// Reloads are driven by SIGHUP from the daemon loop.
type Manager struct {
	path      string
	current   atomic.Pointer[Config]
	reloadErr atomic.Pointer[string]
}

// NewManager loads the config at path and returns a Manager for it.
func NewManager(path string) (*Manager, error) {
	cfg, err := Load(path)
	if err != nil {
		return nil, err
	}
	m := &Manager{path: path}
	m.current.Store(cfg)
	return m, nil
}

// Get returns the current configuration. Never nil.
func (m *Manager) Get() *Config { return m.current.Load() }

// Path returns the config file path this Manager owns.
func (m *Manager) Path() string { return m.path }

// LastError returns the error of the most recent failed reload, or ""
// if the last (re)load succeeded. The running config is never replaced
// by a broken one: on failure the previous config stays active.
func (m *Manager) LastError() string {
	if s := m.reloadErr.Load(); s != nil {
		return *s
	}
	return ""
}

// Reload re-parses the file and atomically swaps the pointer. On error
// the current config is left untouched and the error is retained for
// LastError.
func (m *Manager) Reload() error {
	cfg, err := Load(m.path)
	if err != nil {
		s := err.Error()
		m.reloadErr.Store(&s)
		return err
	}
	m.reloadErr.Store(nil)
	m.current.Store(cfg)
	return nil
}
