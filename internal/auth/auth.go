package auth

import (
	"errors"
	"strings"
	"time"
)

// Sentinel errors for the SMTP layer to map onto reply codes.
var (
	// ErrInvalid means the credentials are wrong.
	ErrInvalid = errors.New("invalid credentials")
	// ErrLocked means the account or source IP is temporarily locked
	// out after too many failures.
	ErrLocked = errors.New("temporarily locked")
)

// dummyHash keeps the timing of "unknown user" close to the timing of
// "wrong password" so the two cannot be told apart.
const dummyHash = "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$q1YkYWjm9jT8sMuqXt8zGJfhY8QhpUKGYs1hK2fBTnM"

// Authenticator verifies credentials against the configured password
// hashes, guarded against brute force. It survives config reloads:
// lookup reads the current configuration on every call, the failure
// state persists.
type Authenticator struct {
	// Lookup returns the stored password hash for an address.
	Lookup func(email string) (hash string, ok bool)
	guard  *Guard
	sleep  func(time.Duration) // injectable for tests
}

// New builds an Authenticator with brute force protection.
func New(lookup func(string) (string, bool), maxFailures int, lockout time.Duration) *Authenticator {
	return &Authenticator{
		Lookup: lookup,
		guard:  NewGuard(maxFailures, lockout),
		sleep:  time.Sleep,
	}
}

// Verify checks email/password from ip. On failure it applies the
// progressive delay before returning, so callers just map the error
// to a reply code.
func (a *Authenticator) Verify(email, password, ip string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	userKey, ipKey := "u:"+email, "ip:"+ip

	if a.guard.Blocked(userKey) || a.guard.Blocked(ipKey) {
		return ErrLocked
	}

	hash, ok := a.Lookup(email)
	if !ok {
		hash = dummyHash // burn comparable time for unknown users
	}
	if !VerifyPassword(hash, password) || !ok {
		d1 := a.guard.Fail(userKey)
		d2 := a.guard.Fail(ipKey)
		if d2 > d1 {
			d1 = d2
		}
		a.sleep(d1)
		return ErrInvalid
	}
	a.guard.Success(userKey)
	a.guard.Success(ipKey)
	return nil
}
