package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/ancyloce/contelys-cloud-identity/internal/application/admission"
	"github.com/ancyloce/contelys-cloud-identity/internal/application/signin"
	"github.com/ancyloce/contelys-cloud-identity/internal/domain/principals"
	"github.com/ancyloce/contelys-cloud-identity/internal/domain/sessions"
	"github.com/ancyloce/contelys-cloud-identity/internal/infrastructure/postgres/gen"
)

// Sessions is the store of sessions.
type Sessions struct{ db *Database }

// Sessions returns the store of sessions.
func (d *Database) Sessions() Sessions { return Sessions{db: d} }

// Live returns the live session of a cookie's value, or admission.ErrNoSession.
func (s Sessions) Live(ctx context.Context, cookie string) (admission.Live, error) {
	row, err := s.db.queries.FindLiveSession(ctx, sessions.Digest(cookie))
	if errors.Is(err, pgx.ErrNoRows) {
		return admission.Live{}, admission.ErrNoSession
	}
	if err != nil {
		return admission.Live{}, err
	}
	return admission.Live{
		Session: row.ID, Principal: row.PrincipalID, AuthorityVersion: row.AuthorityVersion, LimitKey: row.LimitKey,
	}, nil
}

// Create records a new session under the digest of its cookie's value, which is never stored.
func (s Sessions) Create(ctx context.Context, session sessions.Session, cookie string) error {
	return s.db.queries.InsertSession(ctx, gen.InsertSessionParams{
		Digest:       sessions.Digest(cookie),
		ID:           session.ID,
		PrincipalID:  session.Principal,
		LoginSession: session.LoginSession,
		SignedInAt:   timestamp(session.SignedInAt),
	})
}

// Attempts is the store of sign-in attempts.
type Attempts struct{ db *Database }

// Attempts returns the store of sign-in attempts.
func (d *Database) Attempts() Attempts { return Attempts{db: d} }

// Save records an attempt under the digests of its state and of the browser's cookie.
func (a Attempts) Save(ctx context.Context, attempt sessions.Attempt, cookie string) error {
	return a.db.queries.InsertSignInAttempt(ctx, gen.InsertSignInAttemptParams{
		StateDigest:  sessions.Digest(attempt.State),
		CookieDigest: sessions.Digest(cookie),
		Verifier:     attempt.Verifier,
		Nonce:        attempt.Nonce,
		ReturnPath:   attempt.ReturnPath,
		ExpiresAt:    timestamp(attempt.ExpiresAt),
	})
}

// Take removes and returns the attempt of the state and the browser's cookie, or signin.ErrFailed.
func (a Attempts) Take(ctx context.Context, state, cookie string) (sessions.Attempt, error) {
	row, err := a.db.queries.TakeSignInAttempt(ctx, gen.TakeSignInAttemptParams{
		StateDigest: sessions.Digest(state), CookieDigest: sessions.Digest(cookie),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return sessions.Attempt{}, signin.ErrFailed
	}
	if err != nil {
		return sessions.Attempt{}, err
	}
	return sessions.Attempt{State: state, Verifier: row.Verifier, Nonce: row.Nonce, ReturnPath: row.ReturnPath, ExpiresAt: row.ExpiresAt.Time}, nil
}

// Principals is the store of principals and their links to subjects.
type Principals struct{ db *Database }

// Principals returns the store of principals.
func (d *Database) Principals() Principals { return Principals{db: d} }

// ForSubject returns the principal of subject with its name and address refreshed from first, or
// creates first with its link to subject at the subject's first sign-in, in one transaction. When two
// first sign-ins race, the link's uniqueness lets one create the principal, and the other one finds it.
func (p Principals) ForSubject(ctx context.Context, subject principals.Subject, first principals.Principal) (principals.Principal, error) {
	id, err := p.linked(ctx, subject)
	if err != nil {
		return principals.Principal{}, err
	}
	if id == "" {
		created, err := p.create(ctx, subject, first)
		if err != nil || created {
			return first, err
		}
		// Another sign-in of the subject linked its principal first.
		if id, err = p.linked(ctx, subject); err != nil {
			return principals.Principal{}, err
		}
	}
	row, err := p.db.queries.RefreshPrincipal(ctx, gen.RefreshPrincipalParams{ID: id, Name: text(first.Name), Address: text(first.Address)})
	if err != nil {
		return principals.Principal{}, err
	}
	return principal(row), nil
}

// linked is the identifier of the principal that subject is linked to, or "" when it has none.
func (p Principals) linked(ctx context.Context, subject principals.Subject) (string, error) {
	row, err := p.db.queries.FindPrincipalBySubject(ctx, gen.FindPrincipalBySubjectParams{Issuer: subject.Issuer, Subject: subject.Subject})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return row.ID, err
}

// create creates first and its link to subject in one transaction, and reports false without creating
// anything when another sign-in linked the subject first.
func (p Principals) create(ctx context.Context, subject principals.Subject, first principals.Principal) (bool, error) {
	tx, err := p.db.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	queries := p.db.queries.WithTx(tx)
	if err := queries.InsertPrincipal(ctx, gen.InsertPrincipalParams{
		ID: first.ID, State: string(first.State), AuthorityVersion: first.AuthorityVersion, Revision: first.Revision,
		Name: text(first.Name), Address: text(first.Address), LimitKey: first.LimitKey,
	}); err != nil {
		return false, err
	}
	linked, err := queries.InsertSubjectLink(ctx, gen.InsertSubjectLinkParams{Issuer: subject.Issuer, Subject: subject.Subject, PrincipalID: first.ID})
	if err != nil || linked == 0 {
		return false, err
	}
	return true, tx.Commit(ctx)
}

func principal(row gen.Principal) principals.Principal {
	return principals.Principal{
		ID: row.ID, State: principals.State(row.State), AuthorityVersion: row.AuthorityVersion, Revision: row.Revision,
		Name: row.Name.String, Address: row.Address.String, LimitKey: row.LimitKey,
	}
}

func text(s string) pgtype.Text { return pgtype.Text{String: s, Valid: true} }

func timestamp(t time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: t, Valid: true} }
