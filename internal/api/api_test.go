package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/ostap-mykhaylyak/kavira/internal/config"
	"github.com/ostap-mykhaylyak/kavira/internal/reputation"
)

const testKey = "0123456789abcdef0123456789abcdef"

func testAPI(t *testing.T) *Server {
	t.Helper()
	cfg := &config.Config{
		Server:  config.Server{Hostname: "mail.example.com"},
		Domains: []config.Domain{{Name: "example.com"}},
		Users: []config.User{
			{Email: "admin@example.com", Type: "virtual", PasswordHash: "$argon2id$secret"},
			{Email: "info@example.com", Type: "virtual"},
		},
	}
	rep, _ := reputation.Open("")
	rep.Record("user:admin@example.com", reputation.EventSpamComplaint)

	return New(":0", []string{testKey}, Deps{
		Config:     func() *config.Config { return cfg },
		Reload:     func() error { return nil },
		QueueSize:  func() int { return 3 },
		Reputation: rep,
		Version:    "test",
		Started:    time.Now().Add(-time.Minute),
	}, slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
}

// call runs one request against the API's handler.
func call(t *testing.T, s *Server, method, path, key string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = "192.0.2.10:1234"
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	w := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(w, req)
	return w
}

func TestHealthIsUnauthenticated(t *testing.T) {
	s := testAPI(t)
	w := call(t, s, http.MethodGet, "/health", "")
	if w.Code != http.StatusOK {
		t.Fatalf("health without a key = %d, want 200", w.Code)
	}
	var body map[string]any
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["status"] != "ok" {
		t.Errorf("body = %v", body)
	}
	// Health must not leak configuration details.
	if _, ok := body["domains"]; ok {
		t.Error("health must not expose the domain count")
	}
}

func TestAuthRequired(t *testing.T) {
	s := testAPI(t)
	for _, path := range []string{"/api/v1/status", "/api/v1/domains", "/api/v1/users", "/api/v1/reputation"} {
		if w := call(t, s, http.MethodGet, path, ""); w.Code != http.StatusUnauthorized {
			t.Errorf("%s without a key = %d, want 401", path, w.Code)
		}
		if w := call(t, s, http.MethodGet, path, "wrong-key"); w.Code != http.StatusUnauthorized {
			t.Errorf("%s with a bad key = %d, want 401", path, w.Code)
		}
		if w := call(t, s, http.MethodGet, path, testKey); w.Code != http.StatusOK {
			t.Errorf("%s with the right key = %d, want 200", path, w.Code)
		}
	}
}

func TestXAPIKeyHeaderAccepted(t *testing.T) {
	s := testAPI(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.RemoteAddr = "192.0.2.10:1234"
	req.Header.Set("X-API-Key", testKey)
	w := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("X-API-Key = %d, want 200", w.Code)
	}
}

func TestStatusAndDomains(t *testing.T) {
	s := testAPI(t)
	w := call(t, s, http.MethodGet, "/api/v1/status", testKey)
	var st map[string]any
	json.Unmarshal(w.Body.Bytes(), &st)
	if st["hostname"] != "mail.example.com" || st["version"] != "test" {
		t.Errorf("status = %v", st)
	}
	if st["queue"].(float64) != 3 {
		t.Errorf("queue size = %v", st["queue"])
	}

	w = call(t, s, http.MethodGet, "/api/v1/domains", testKey)
	var dom map[string][]map[string]any
	json.Unmarshal(w.Body.Bytes(), &dom)
	if len(dom["domains"]) != 1 || dom["domains"][0]["name"] != "example.com" {
		t.Errorf("domains = %v", dom)
	}
	if dom["domains"][0]["storage"] != "virtual" {
		t.Errorf("storage should default to virtual: %v", dom["domains"][0])
	}
}

func TestUsersNeverExposePasswordHash(t *testing.T) {
	s := testAPI(t)
	w := call(t, s, http.MethodGet, "/api/v1/users", testKey)
	raw := w.Body.String()
	if len(raw) == 0 {
		t.Fatal("empty body")
	}
	// The response must carry no hash material at all.
	for _, forbidden := range []string{"argon2id", "password", "secret", "hash"} {
		if containsFold(raw, forbidden) {
			t.Errorf("users response leaks %q:\n%s", forbidden, raw)
		}
	}
	var out map[string][]map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	users := out["users"]
	if len(users) != 2 {
		t.Fatalf("users = %v", users)
	}
	if users[0]["can_submit"] != true || users[1]["can_submit"] != false {
		t.Errorf("can_submit wrong: %v", users)
	}
}

func containsFold(haystack, needle string) bool {
	h, n := []rune(haystack), []rune(needle)
	lower := func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + 32
		}
		return r
	}
	for i := 0; i+len(n) <= len(h); i++ {
		ok := true
		for j := range n {
			if lower(h[i+j]) != lower(n[j]) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func TestReloadRequiresPost(t *testing.T) {
	s := testAPI(t)
	if w := call(t, s, http.MethodGet, "/api/v1/reload", testKey); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET reload = %d, want 405", w.Code)
	}
	if w := call(t, s, http.MethodPost, "/api/v1/reload", testKey); w.Code != http.StatusOK {
		t.Errorf("POST reload = %d, want 200", w.Code)
	}
}

func TestReputationEndpoint(t *testing.T) {
	s := testAPI(t)
	w := call(t, s, http.MethodGet, "/api/v1/reputation", testKey)
	var out map[string][]map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	if len(out["reputation"]) != 1 {
		t.Fatalf("reputation = %v", out)
	}
	if out["reputation"][0]["key"] != "user:admin@example.com" {
		t.Errorf("entry = %v", out["reputation"][0])
	}
	if out["reputation"][0]["score"].(float64) != 35 {
		t.Errorf("score = %v, want 35", out["reputation"][0]["score"])
	}
}

func TestAuthRateLimited(t *testing.T) {
	s := testAPI(t)
	// The limiter allows 60/minute per IP; the 61st is throttled,
	// so the API cannot be used as a key-guessing oracle.
	var lastCode int
	for i := 0; i < 62; i++ {
		lastCode = call(t, s, http.MethodGet, "/api/v1/status", "wrong").Code
	}
	if lastCode != http.StatusTooManyRequests {
		t.Errorf("after 62 attempts code = %d, want 429", lastCode)
	}
}
