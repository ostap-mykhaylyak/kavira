// Package auth verifies user credentials and enforces the brute
// force protections: progressive delays and temporary lockouts.
//
// Passwords are never stored in clear. Supported hash formats:
//
//	$argon2id$v=19$m=...,t=...,p=...$<salt>$<key>   (PHC string)
//	$2a$ / $2b$ / $2y$                              (bcrypt)
//
// CRAM-MD5 is deliberately not offered: it requires the server to
// keep plaintext-equivalent secrets, which contradicts hashed-only
// storage. PLAIN and LOGIN over TLS are the supported mechanisms.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// Argon2id parameters for newly generated hashes (RFC 9106 second
// recommended option: 64 MiB, t=3).
const (
	argonMemory  = 64 * 1024
	argonTime    = 3
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

// HashArgon2id derives a PHC-formatted Argon2id hash for password.
func HashArgon2id(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	b64 := base64.RawStdEncoding.EncodeToString
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, b64(salt), b64(key)), nil
}

// VerifyPassword checks password against a stored hash, dispatching
// on the hash format. Unknown formats verify as false.
func VerifyPassword(hash, password string) bool {
	switch {
	case strings.HasPrefix(hash, "$argon2id$"):
		return verifyArgon2id(hash, password)
	case strings.HasPrefix(hash, "$2a$"), strings.HasPrefix(hash, "$2b$"), strings.HasPrefix(hash, "$2y$"):
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
	}
	return false
}

func verifyArgon2id(phc, password string) bool {
	// $argon2id$v=19$m=65536,t=3,p=4$salt$key
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	if m == 0 || t == 0 || p == 0 || m > 1024*1024 {
		return false // refuse absurd parameters
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// KnownHashFormat reports whether hash looks like a supported format,
// for configuration validation.
func KnownHashFormat(hash string) bool {
	return strings.HasPrefix(hash, "$argon2id$") ||
		strings.HasPrefix(hash, "$2a$") ||
		strings.HasPrefix(hash, "$2b$") ||
		strings.HasPrefix(hash, "$2y$")
}
