// Package sessions is a browser's session at Identity and the sign-in attempt that leads to it (design
// section 04). A cookie carries a random secret, of which Identity stores only the digest.
package sessions

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"time"
)

// NewSecret returns a random 256-bit value, as a cookie carries it.
func NewSecret() string {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	return base64.RawURLEncoding.EncodeToString(secret)
}

// Digest is what Identity stores of a secret.
func Digest(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// Session is one browser's session of a principal.
type Session struct {
	// ID travels in the internal token as its sid. It is not the cookie's value.
	ID        string
	Principal string
	// LoginSession is Keycloak's login-session identifier, the sid of its ID token.
	LoginSession string
	SignedInAt   time.Time
}

// New returns the session that a sign-in of principal at now starts.
func New(principal, loginSession string, now time.Time) Session {
	return Session{ID: rand.Text(), Principal: principal, LoginSession: loginSession, SignedInAt: now}
}

// AttemptLifetime is how long a sign-in attempt can be completed.
const AttemptLifetime = 10 * time.Minute

// ErrInvalidReturnPath is a return path that is not a path of the application origin.
var ErrInvalidReturnPath = errors.New("the return path is not a path of the application origin")

// Attempt is one sign-in that a browser started: the state that Keycloak hands back, the PKCE
// verifier, the nonce that the ID token must carry, and the path to return to. It is used once.
type Attempt struct {
	State, Verifier, Nonce, ReturnPath string
	ExpiresAt                          time.Time
}

// NewAttempt starts a sign-in at now that returns to returnPath, or to / when it is empty.
func NewAttempt(returnPath string, now time.Time) (Attempt, error) {
	if returnPath == "" {
		returnPath = "/"
	}
	if !ownPath(returnPath) {
		return Attempt{}, ErrInvalidReturnPath
	}
	return Attempt{
		State:      NewSecret(),
		Verifier:   NewSecret(),
		Nonce:      NewSecret(),
		ReturnPath: returnPath,
		ExpiresAt:  now.Add(AttemptLifetime),
	}, nil
}

// Expired reports whether the attempt can no longer be completed at now.
func (a Attempt) Expired(now time.Time) bool {
	return !now.Before(a.ExpiresAt)
}

// ownPath reports whether p is a path of the application origin, so that a redirect to it stays on
// that origin: one leading slash, no backslash that a browser reads as one, and no scheme or host.
func ownPath(p string) bool {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.ContainsAny(p, "\\\r\n\t") {
		return false
	}
	u, err := url.Parse(p)
	return err == nil && u.Scheme == "" && u.Host == "" && u.User == nil
}
