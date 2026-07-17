package auth

import (
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestArgon2idRoundTrip(t *testing.T) {
	h, err := HashArgon2id("s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(h, "s3cret") {
		t.Error("correct password rejected")
	}
	if VerifyPassword(h, "wrong") {
		t.Error("wrong password accepted")
	}
}

func TestBcryptVerify(t *testing.T) {
	h, err := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(string(h), "s3cret") {
		t.Error("correct password rejected")
	}
	if VerifyPassword(string(h), "wrong") {
		t.Error("wrong password accepted")
	}
}

func TestUnknownFormatRejected(t *testing.T) {
	if VerifyPassword("plaintext", "plaintext") {
		t.Error("plaintext must never verify")
	}
	if VerifyPassword("$1$md5crypt$xxxx", "x") {
		t.Error("unsupported format must not verify")
	}
	if KnownHashFormat("plaintext") {
		t.Error("plaintext is not a known format")
	}
	if !KnownHashFormat("$argon2id$v=19$m=1,t=1,p=1$a$b") {
		t.Error("argon2id must be known")
	}
}

func TestGuardProgressiveDelayAndLockout(t *testing.T) {
	now := time.Unix(0, 0)
	g := NewGuard(3, 15*time.Minute)
	g.now = func() time.Time { return now }

	if d := g.Fail("k"); d != 250*time.Millisecond {
		t.Errorf("first delay = %v", d)
	}
	if d := g.Fail("k"); d != 500*time.Millisecond {
		t.Errorf("second delay = %v", d)
	}
	if g.Blocked("k") {
		t.Fatal("not yet locked")
	}
	g.Fail("k") // third failure locks
	if !g.Blocked("k") {
		t.Fatal("want locked after maxFailures")
	}
	now = now.Add(16 * time.Minute)
	if g.Blocked("k") {
		t.Fatal("lockout must expire")
	}
	g.Success("k")
	if d := g.Fail("k"); d != 250*time.Millisecond {
		t.Errorf("delay after success reset = %v", d)
	}
}

func testAuthenticator(hash string) *Authenticator {
	a := New(func(email string) (string, bool) {
		if email == "admin@example.com" {
			return hash, true
		}
		return "", false
	}, 3, 15*time.Minute)
	a.sleep = func(time.Duration) {}
	return a
}

func TestVerifyFlow(t *testing.T) {
	h, _ := HashArgon2id("pw")
	a := testAuthenticator(h)

	if err := a.Verify("Admin@Example.com", "pw", "1.2.3.4"); err != nil {
		t.Fatalf("valid login: %v", err)
	}
	if err := a.Verify("admin@example.com", "wrong", "1.2.3.4"); err != ErrInvalid {
		t.Fatalf("wrong password: %v", err)
	}
	if err := a.Verify("ghost@example.com", "pw", "1.2.3.4"); err != ErrInvalid {
		t.Fatalf("unknown user: %v", err)
	}
}

func TestVerifyLockout(t *testing.T) {
	h, _ := HashArgon2id("pw")
	a := testAuthenticator(h)

	for i := 0; i < 3; i++ {
		a.Verify("admin@example.com", "wrong", "1.2.3.4")
	}
	// Even the correct password is refused while locked.
	if err := a.Verify("admin@example.com", "pw", "1.2.3.4"); err != ErrLocked {
		t.Fatalf("want ErrLocked, got %v", err)
	}
	// The IP is locked too: other users from it are refused.
	if err := a.Verify("other@example.com", "x", "1.2.3.4"); err != ErrLocked {
		t.Fatalf("want ErrLocked for same IP, got %v", err)
	}
}
