// Package signin signs a browser in, as Keycloak's confidential client with PKCE (design section 04,
// ADR 0051): it starts an attempt that it binds to the browser, and completes it from Keycloak's code
// with a principal and a session. Identity keeps none of Keycloak's tokens (Identity ADR 0005).
package signin

import (
	"context"
	"errors"
	"time"

	"github.com/ancyloce/contelys-cloud-identity/internal/domain/principals"
	"github.com/ancyloce/contelys-cloud-identity/internal/domain/sessions"
)

// The ways a sign-in fails. Any other error means that Keycloak or the database cannot be reached.
var (
	// ErrFailed is a callback whose attempt, Keycloak's answer or ID token does not hold.
	ErrFailed = errors.New("the sign-in failed")
	// ErrNotActive is a principal that is disabled or erased.
	ErrNotActive = errors.New("the principal is not active")
)

// Attempts keeps the sign-in attempts, bound to the value of the browser's cookie. Take returns the
// attempt of the state and the cookie and removes it, so that it is used once; without one it returns
// ErrFailed.
type Attempts interface {
	Save(ctx context.Context, attempt sessions.Attempt, cookie string) error
	Take(ctx context.Context, state, cookie string) (sessions.Attempt, error)
}

// Assertion is what a verified ID token asserts about the person who signed in.
type Assertion struct {
	Subject principals.Subject
	// Address is verified, and Name is the person's name.
	Address, Name string
	// LoginSession is Keycloak's login-session identifier.
	LoginSession string
}

// Keycloak is the realm's authorization server. Exchange returns ErrFailed when Keycloak refuses the
// code or the ID token does not verify against the attempt's nonce.
type Keycloak interface {
	AuthorizationURL(attempt sessions.Attempt) string
	Exchange(ctx context.Context, code string, attempt sessions.Attempt) (Assertion, error)
}

// Principals finds the principal of a subject or, at its first sign-in, creates first as its
// principal, and refreshes the copies of its name and address. Two sign-ins of one subject give one
// principal.
type Principals interface {
	ForSubject(ctx context.Context, subject principals.Subject, first principals.Principal) (principals.Principal, error)
}

// Sessions records a new session under the value of its cookie.
type Sessions interface {
	Create(ctx context.Context, session sessions.Session, cookie string) error
}

// Service is the use case of sign-in.
type Service struct {
	Attempts   Attempts
	Keycloak   Keycloak
	Principals Principals
	Sessions   Sessions
	Now        func() time.Time
}

// Started is a sign-in that a browser starts: where to send it, and the value of the cookie that binds
// the attempt to it.
type Started struct {
	Location, Cookie string
}

// Start records an attempt that returns to returnPath and binds it to the browser. It returns
// sessions.ErrInvalidReturnPath for a path that is not of the application origin.
func (s Service) Start(ctx context.Context, returnPath string) (Started, error) {
	attempt, err := sessions.NewAttempt(returnPath, s.Now())
	if err != nil {
		return Started{}, err
	}
	cookie := sessions.NewSecret()
	if err := s.Attempts.Save(ctx, attempt, cookie); err != nil {
		return Started{}, err
	}
	return Started{Location: s.Keycloak.AuthorizationURL(attempt), Cookie: cookie}, nil
}

// Callback is what a browser brings back from Keycloak: the value of its attempt's cookie, and the
// state, the code and the error that Keycloak put into the callback's query.
type Callback struct {
	Cookie, State, Code, Error string
}

// Completed is a finished sign-in: the value of the session cookie, and the path to return to.
type Completed struct {
	Cookie, ReturnPath string
}

// Complete finishes the attempt that the callback names, with Keycloak's code, or fails with ErrFailed
// when Keycloak reported an error or anything does not hold, and with ErrNotActive for a principal that
// may not sign in. A failed sign-in creates no session.
func (s Service) Complete(ctx context.Context, callback Callback) (Completed, error) {
	if callback.Cookie == "" || callback.State == "" {
		return Completed{}, ErrFailed
	}
	attempt, err := s.Attempts.Take(ctx, callback.State, callback.Cookie)
	if err != nil {
		return Completed{}, err
	}
	now := s.Now()
	if callback.Error != "" || callback.Code == "" || attempt.Expired(now) {
		return Completed{}, ErrFailed
	}
	assertion, err := s.Keycloak.Exchange(ctx, callback.Code, attempt)
	if err != nil {
		return Completed{}, err
	}
	principal, err := s.Principals.ForSubject(ctx, assertion.Subject, principals.New(assertion.Name, assertion.Address))
	if err != nil {
		return Completed{}, err
	}
	if principal.State != principals.Active {
		return Completed{}, ErrNotActive
	}
	cookie := sessions.NewSecret()
	if err := s.Sessions.Create(ctx, sessions.New(principal.ID, assertion.LoginSession, now), cookie); err != nil {
		return Completed{}, err
	}
	return Completed{Cookie: cookie, ReturnPath: attempt.ReturnPath}, nil
}
