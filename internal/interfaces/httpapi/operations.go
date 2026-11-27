package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/ancyloce/contelys-cloud-identity/internal/application/admission"
	"github.com/ancyloce/contelys-cloud-identity/internal/application/signin"
	"github.com/ancyloce/contelys-cloud-identity/internal/application/tokens"
	"github.com/ancyloce/contelys-cloud-identity/internal/domain/sessions"
	"github.com/ancyloce/contelys-cloud-identity/internal/interfaces/httpapi/gen"
)

// UseCases are what the operations of the contract call.
type UseCases struct {
	SignIn    signin.Service
	Admission admission.Service
	KeySet    tokens.KeySet
	// Logger records why an operation could not be completed, which its answer never says.
	Logger *slog.Logger
}

// limitKeyHeader is the header of an admitted answer that carries the limit key (design section 05).
const limitKeyHeader = "X-Contelys-Limit-Key"

// The cookies of a browser at Identity (design section 04).
const (
	signInCookie  = "__Host-sign-in"
	sessionCookie = "__Host-session"
)

// cookie is a cookie of the prefix __Host-, which binds it to the application origin: Secure, Path=/
// and no Domain, and HttpOnly besides. A maxAge of 0 makes it last for the browser's session, and a
// negative one clears it.
func cookie(name, value string, maxAge int, sameSite http.SameSite) *http.Cookie {
	return &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: maxAge, Secure: true, HttpOnly: true, SameSite: sameSite}
}

// operations serves the operations of Identity's contract. An operation that its ticket has not
// built yet answers 503 unavailable, which every operation of the contract may answer, with
// Cache-Control no-store, which those of registration and sign-in require.
type operations struct {
	UseCases
}

var _ gen.ServerInterface = operations{}

func (operations) Register(w http.ResponseWriter, r *http.Request) { unavailable(w, r) }

// StartSignIn records an attempt, binds it to the browser with the cookie __Host-sign-in, which is
// SameSite=Lax because the callback arrives through a redirect from Keycloak's host, and redirects the
// browser to Keycloak.
func (o operations) StartSignIn(w http.ResponseWriter, r *http.Request, params gen.StartSignInParams) {
	w.Header().Set("Cache-Control", "no-store")
	started, err := o.SignIn.Start(r.Context(), optional(params.ReturnTo))
	switch {
	case errors.Is(err, sessions.ErrInvalidReturnPath):
		writeProblem(w, r, http.StatusBadRequest, gen.IdentityErrorCodeInvalidReturnPath, invalidReturnPathTitle)
	case err != nil:
		o.failed(w, r, "startSignIn", err)
	default:
		http.SetCookie(w, cookie(signInCookie, started.Cookie, int(sessions.AttemptLifetime.Seconds()), http.SameSiteLaxMode))
		w.Header().Set("Location", started.Location)
		w.WriteHeader(http.StatusFound)
	}
}

// CompleteSignIn completes the attempt of the browser's cookie with Keycloak's code, clears the
// attempt's cookie, sets the session cookie, which is SameSite=Strict, and returns the browser to the
// attempt's path. A callback that fails leaves the browser's cookie alone, so that a forged callback
// cannot end a sign-in that the browser has under way.
func (o operations) CompleteSignIn(w http.ResponseWriter, r *http.Request, params gen.CompleteSignInParams) {
	w.Header().Set("Cache-Control", "no-store")
	completed, err := o.SignIn.Complete(r.Context(), signin.Callback{
		Cookie: optional(params.UnderscoreUnderscoreHostSignIn),
		State:  optional(params.State),
		Code:   optional(params.Code),
		Error:  optional(params.Error),
	})
	switch {
	case errors.Is(err, signin.ErrFailed):
		o.Logger.InfoContext(r.Context(), "a sign-in failed", "error", err)
		writeProblem(w, r, http.StatusBadRequest, gen.IdentityErrorCodeSignInFailed, signInFailedTitle)
	case errors.Is(err, signin.ErrNotActive):
		writeProblem(w, r, http.StatusForbidden, gen.IdentityErrorCodePrincipalNotActive, notActiveTitle)
	case err != nil:
		o.failed(w, r, "completeSignIn", err)
	default:
		http.SetCookie(w, cookie(signInCookie, "", -1, http.SameSiteLaxMode))
		http.SetCookie(w, cookie(sessionCookie, completed.Cookie, 0, http.SameSiteStrictMode))
		w.Header().Set("Location", completed.ReturnPath)
		w.WriteHeader(http.StatusFound)
	}
}

func (operations) SignOut(w http.ResponseWriter, r *http.Request) { unavailable(w, r) }

func (operations) GetMe(w http.ResponseWriter, r *http.Request) { unavailable(w, r) }

// Authenticate decides admission for Edge (design section 05). An admitted request gets the internal
// token and the limit key, and no body and no cookie; a request without a live session gets 401 with
// WWW-Authenticate: Session.
func (o operations) Authenticate(w http.ResponseWriter, r *http.Request, params gen.AuthenticateParams) {
	admitted, err := o.Admission.Admit(r.Context(), optional(params.UnderscoreUnderscoreHostSession), params.XRequestId)
	switch {
	case errors.Is(err, admission.ErrNoSession):
		w.Header().Set("WWW-Authenticate", "Session")
		writeProblem(w, r, http.StatusUnauthorized, gen.IdentityErrorCodeSessionRequired, sessionRequiredTitle)
	case err != nil:
		o.failed(w, r, "authenticate", err)
	default:
		w.Header().Set("Authorization", "Bearer "+admitted.Token)
		w.Header().Set(limitKeyHeader, admitted.LimitKey)
		w.WriteHeader(http.StatusOK)
	}
}

// GetKeys publishes the keys that verify Identity's tokens, as Ed25519 keys of RFC 8037.
func (o operations) GetKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := o.KeySet.Keys()
	if err != nil {
		o.failed(w, r, "getKeys", err)
		return
	}
	set := gen.JsonWebKeySet{Keys: []gen.Ed25519Key{}}
	for _, key := range keys {
		set.Keys = append(set.Keys, gen.Ed25519Key{
			Kty: gen.OKP, Crv: gen.Ed25519, Alg: gen.EdDSA, Use: gen.Sig,
			Kid: key.ID, X: base64.RawURLEncoding.EncodeToString(key.Key),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(set)
}

func (operations) IssueWorkloadToken(w http.ResponseWriter, r *http.Request) { unavailable(w, r) }

func (operations) LookUpPrincipals(w http.ResponseWriter, r *http.Request) { unavailable(w, r) }

func (operations) ReceiveBackChannelLogout(w http.ResponseWriter, r *http.Request) { unavailable(w, r) }

// optional is the value of an optional parameter, or "" without one.
func optional(parameter *string) string {
	if parameter == nil {
		return ""
	}
	return *parameter
}

// failed answers 503 for an operation that could not be completed, and records why.
func (o operations) failed(w http.ResponseWriter, r *http.Request, operation string, err error) {
	o.Logger.WarnContext(r.Context(), "an operation could not be completed", "operation", operation, "error", err)
	unavailable(w, r)
}

func unavailable(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeProblem(w, r, http.StatusServiceUnavailable, gen.IdentityErrorCodeUnavailable, unavailableTitle)
}

// invalidParameter answers a request whose parameters do not match the contract. On the
// authentication endpoint it answers 503: a call that lacks or misforms a header that Edge always
// sends is Edge's defect (design section 05). The headers there that the client controls, the cookie,
// Origin and the trace context, are refused for nothing, so admission must decide on them by the
// cross-site and session rules instead, not reach this answer. Every other operation answers 400
// invalid_request, which says nothing about any account.
func invalidParameter(w http.ResponseWriter, r *http.Request, _ error) {
	if r.Pattern == authenticationPattern {
		unavailable(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeProblem(w, r, http.StatusBadRequest, gen.IdentityErrorCodeInvalidRequest, invalidRequestTitle)
}
