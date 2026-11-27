// Package tokens is what Identity signs, and the port through which the use cases sign it: the internal
// token of an admitted request (design section 05, ADR 0052), and the keys that verify it.
package tokens

import (
	"crypto/ed25519"
	"time"
)

// InternalLifetime is how long an internal token is valid.
const InternalLifetime = 60 * time.Second

// Internal is the content of an internal token.
type Internal struct {
	// Principal is its sub, and Session its sid, the session's identifier.
	Principal, Session string
	// AuthorityVersion is the principal's authority version when the request was admitted.
	AuthorityVersion int64
	// RequestID is the request ID that Edge sent, which becomes the token's jti.
	RequestID        string
	IssuedAt, Expiry time.Time
}

// PublicKey is a key that verifies tokens, named by its key ID.
type PublicKey struct {
	ID  string
	Key ed25519.PublicKey
}

// Signer signs tokens and publishes the keys that verify them.
type Signer interface {
	SignInternal(Internal) (string, error)
	PublicKeys() ([]PublicKey, error)
}

// KeySet is the use case of the key set: the keys that verify Identity's tokens, which any deployable
// reads without a token (design section 05).
type KeySet struct {
	Signer Signer
}

// Keys returns the keys of the key set.
func (k KeySet) Keys() ([]PublicKey, error) {
	return k.Signer.PublicKeys()
}
