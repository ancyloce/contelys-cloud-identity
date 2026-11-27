// Package principals is the principal (design section 08): the one record of a person that Identity
// admits. An issuer and a subject that Keycloak asserts map to exactly one principal, whose identifier
// is random and never reused. An address is never an identifier.
package principals

import (
	"crypto/rand"
	"encoding/base64"
)

// State is whether a principal may use the application.
type State string

// The states of a principal.
const (
	Active   State = "active"
	Disabled State = "disabled"
	Erased   State = "erased"
)

// Principal is a person whom Identity admits.
type Principal struct {
	ID    string
	State State
	// AuthorityVersion only rises (ADR 0050), and Revision rises with every event of the principal.
	AuthorityVersion int64
	Revision         int64
	// Name and Address are copies of what Keycloak asserts, refreshed at each sign-in.
	Name, Address string
	// LimitKey names the principal in Edge's rate limits. It is not the identifier and never changes.
	LimitKey string
}

// Subject is who Keycloak asserts a person is.
type Subject struct {
	Issuer, Subject string
}

// New returns the principal of a person's first sign-in: active, at authority version 1 and revision
// 1, with a random identifier and a random limit key.
func New(name, address string) Principal {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return Principal{
		ID:               rand.Text(),
		State:            Active,
		AuthorityVersion: 1,
		Revision:         1,
		Name:             name,
		Address:          address,
		LimitKey:         base64.RawURLEncoding.EncodeToString(key),
	}
}
