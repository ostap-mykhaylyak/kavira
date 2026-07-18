// Package api serves the administrative HTTPS API.
//
// Authentication is static API keys only, by design: no JWT, no
// sessions, no refresh flow. A key is presented as
// "Authorization: Bearer <key>" (or X-API-Key) and compared in
// constant time. The API never runs without TLS and never without at
// least one key — the configuration refuses to load otherwise.
//
// /health is the only unauthenticated endpoint, so a load balancer
// can probe the daemon without holding a credential.
package api

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ostap-mykhaylyak/kavira/internal/config"
	"github.com/ostap-mykhaylyak/kavira/internal/ratelimit"
	"github.com/ostap-mykhaylyak/kavira/internal/reputation"
)

// Deps are the live objects the API reports on and acts upon.
type Deps struct {
	// Config returns the current configuration.
	Config func() *config.Config
	// Reload asks the daemon to re-read its configuration.
	Reload func() error
	// QueueSize reports the outbound queue depth.
	QueueSize func() int
	// Reputation is the score store, may be nil.
	Reputation *reputation.Store
	// Version is the running binary's version.
	Version string
	// Started is the daemon start time, for uptime.
	Started time.Time
}

// Server is the admin API.
type Server struct {
	deps Deps
	keys []string
	log  *slog.Logger
	// limiter throttles authentication attempts per source IP, so the
	// API cannot be used as a key-guessing oracle.
	limiter *ratelimit.Limiter

	http *http.Server
}

// New builds the API server. keys must be non-empty; the config
// validation guarantees it.
func New(addr string, keys []string, deps Deps, log *slog.Logger) *Server {
	s := &Server{
		deps:    deps,
		keys:    keys,
		log:     log,
		limiter: ratelimit.New(60, time.Minute),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/api/v1/status", s.auth(s.handleStatus))
	mux.HandleFunc("/api/v1/domains", s.auth(s.handleDomains))
	mux.HandleFunc("/api/v1/users", s.auth(s.handleUsers))
	mux.HandleFunc("/api/v1/reputation", s.auth(s.handleReputation))
	mux.HandleFunc("/api/v1/reload", s.auth(s.handleReload))

	s.http = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return s
}

// Serve runs the API over an already-TLS listener.
func (s *Server) Serve(ln net.Listener) error {
	err := s.http.Serve(ln)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// Shutdown stops the API.
func (s *Server) Shutdown(timeout time.Duration) {
	s.http.Close()
}

// auth wraps a handler with API key verification.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if !s.limiter.Allow(ip) {
			s.log.Warn("api rate limited",
				"event", "api_ratelimit", "ip", ip, "path", r.URL.Path, "action", "reject")
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many requests"})
			return
		}
		if !s.validKey(presentedKey(r)) {
			s.log.Warn("api authentication failed",
				"event", "api_auth_failed", "ip", ip, "path", r.URL.Path, "action", "reject")
			w.Header().Set("WWW-Authenticate", `Bearer realm="kavira"`)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid api key"})
			return
		}
		next(w, r)
	}
}

// presentedKey extracts the key from either accepted header.
func presentedKey(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		if after, ok := strings.CutPrefix(h, "Bearer "); ok {
			return strings.TrimSpace(after)
		}
	}
	return strings.TrimSpace(r.Header.Get("X-API-Key"))
}

// validKey compares in constant time against every configured key, so
// a timing side channel cannot reveal a prefix.
func (s *Server) validKey(presented string) bool {
	if presented == "" {
		return false
	}
	ok := false
	for _, k := range s.keys {
		if subtle.ConstantTimeCompare([]byte(k), []byte(presented)) == 1 {
			ok = true
		}
	}
	return ok
}

func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// handleHealth is unauthenticated: it reveals only liveness.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"uptime": time.Since(s.deps.Started).Round(time.Second).String(),
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	cfg := s.deps.Config()
	writeJSON(w, http.StatusOK, map[string]any{
		"version":  s.deps.Version,
		"hostname": cfg.Server.Hostname,
		"uptime":   time.Since(s.deps.Started).Round(time.Second).String(),
		"domains":  len(cfg.Domains),
		"users":    len(cfg.Users),
		"queue":    s.deps.QueueSize(),
	})
}

func (s *Server) handleDomains(w http.ResponseWriter, r *http.Request) {
	cfg := s.deps.Config()
	type domainInfo struct {
		Name         string `json:"name"`
		Storage      string `json:"storage"`
		DKIMSelector string `json:"dkim_selector,omitempty"`
	}
	out := make([]domainInfo, 0, len(cfg.Domains))
	for _, d := range cfg.Domains {
		st := d.Storage.Type
		if st == "" {
			st = config.StorageVirtual
		}
		out = append(out, domainInfo{Name: d.Name, Storage: st, DKIMSelector: d.DKIMSelector})
	}
	writeJSON(w, http.StatusOK, map[string]any{"domains": out})
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	cfg := s.deps.Config()
	type userInfo struct {
		Email string `json:"email"`
		Type  string `json:"type"`
		// The password hash is never exposed, not even to an
		// authenticated caller: the API has no reason to hand out
		// material an offline cracker could work on.
		CanSubmit bool `json:"can_submit"`
	}
	out := make([]userInfo, 0, len(cfg.Users))
	for _, u := range cfg.Users {
		out = append(out, userInfo{Email: u.Email, Type: u.Type, CanSubmit: u.PasswordHash != ""})
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

func (s *Server) handleReputation(w http.ResponseWriter, r *http.Request) {
	if s.deps.Reputation == nil {
		writeJSON(w, http.StatusOK, map[string]any{"reputation": []any{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"reputation": s.deps.Reputation.Snapshot()})
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use POST"})
		return
	}
	if err := s.deps.Reload(); err != nil {
		s.log.Error("api reload failed", "error", err.Error())
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprint(err)})
		return
	}
	s.log.Info("configuration reloaded via api", "event", "api_reload", "ip", clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "reloaded"})
}
