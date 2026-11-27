// Package admission decides, for every request on a route that is not anonymous, whether its caller is
// admitted, from the current state in the database and never from a cache (design section 05,
// Identity ADR 0004).
package admission

import (
	"context"
	"errors"
	"time"

	"github.com/ancyloce/contelys-cloud-identity/internal/application/tokens"
)

// ErrNoSession is a request without a live session: no cookie, or a cookie that is no live session's.
var ErrNoSession = errors.New("no live session")

// Live is a session that has not ended, with what admission needs of its principal.
type Live struct {
	Session, Principal string
	AuthorityVersion   int64
	LimitKey           string
}

// Sessions finds the live session of a cookie's value, or returns ErrNoSession.
type Sessions interface {
	Live(ctx context.Context, cookie string) (Live, error)
}

// Admitted is what an admitted request carries on: the internal token in place of the cookie, and the
// caller's limit key.
type Admitted struct {
	Token, LimitKey string
}

// Service is the use case of admission.
type Service struct {
	Sessions Sessions
	Tokens   tokens.Signer
	Now      func() time.Time
}

// Admit decides for a request that carries cookie, the value of the session cookie, and requestID, the
// request ID that Edge set.
func (s Service) Admit(ctx context.Context, cookie, requestID string) (Admitted, error) {
	if cookie == "" {
		return Admitted{}, ErrNoSession
	}
	live, err := s.Sessions.Live(ctx, cookie)
	if err != nil {
		return Admitted{}, err
	}
	now := s.Now()
	token, err := s.Tokens.SignInternal(tokens.Internal{
		Principal:        live.Principal,
		Session:          live.Session,
		AuthorityVersion: live.AuthorityVersion,
		RequestID:        requestID,
		IssuedAt:         now,
		Expiry:           now.Add(tokens.InternalLifetime),
	})
	if err != nil {
		return Admitted{}, err
	}
	return Admitted{Token: token, LimitKey: live.LimitKey}, nil
}
