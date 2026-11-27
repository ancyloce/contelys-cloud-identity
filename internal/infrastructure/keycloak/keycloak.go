// Package keycloak is the only code that talks to Keycloak (design section 02). It signs browsers in as
// the realm's confidential client with PKCE (S256), with the endpoints configured statically and no
// discovery (ADR 0064): the authorization endpoint and the issuer on the authentication hostname, the
// token and keys endpoints on Keycloak's internal address. It keeps none of Keycloak's tokens.
package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"

	"github.com/ancyloce/contelys-cloud-identity/internal/application/signin"
	"github.com/ancyloce/contelys-cloud-identity/internal/domain/principals"
	"github.com/ancyloce/contelys-cloud-identity/internal/domain/sessions"
)

// algorithm is the one algorithm that Identity accepts on an ID token, the realm's RS256.
const algorithm = oidc.RS256

// Settings say where Keycloak is and which client Identity is.
type Settings struct {
	// PublicURL is the authentication hostname, and InternalURL Keycloak's internal address.
	PublicURL, InternalURL string
	Realm                  string
	// ClientID is the client identity, ClientSecretFile holds its secret, and RedirectURL is its one
	// callback.
	ClientID, ClientSecretFile, RedirectURL string
	// Client calls Keycloak's internal address, trusting the installation's certificate authority.
	Client *http.Client
}

// Keycloak is the realm's authorization server.
type Keycloak struct {
	oauth      oauth2.Config
	secretFile string
	verifier   *oidc.IDTokenVerifier
	client     *http.Client
}

var _ signin.Keycloak = (*Keycloak)(nil)

// New returns the realm of settings. It reads the client's secret for each code exchange, so that an
// instance without it still starts and decides admission, and fetches the realm's keys when it first
// verifies an ID token.
func New(settings Settings) *Keycloak {
	realm := "/realms/" + url.PathEscape(settings.Realm)
	issuer := strings.TrimSuffix(settings.PublicURL, "/") + realm
	internal := strings.TrimSuffix(settings.InternalURL, "/") + realm + "/protocol/openid-connect"
	keys := &keySet{url: internal + "/certs", client: settings.Client}
	return &Keycloak{
		oauth: oauth2.Config{
			ClientID: settings.ClientID,
			Endpoint: oauth2.Endpoint{
				AuthURL:   issuer + "/protocol/openid-connect/auth",
				TokenURL:  internal + "/token",
				AuthStyle: oauth2.AuthStyleInHeader,
			},
			RedirectURL: settings.RedirectURL,
			Scopes:      []string{oidc.ScopeOpenID},
		},
		secretFile: settings.ClientSecretFile,
		verifier:   oidc.NewVerifier(issuer, keys, &oidc.Config{ClientID: settings.ClientID, SupportedSigningAlgs: []string{algorithm}}),
		client:     settings.Client,
	}
}

// AuthorizationURL is where a browser signs in for attempt: Keycloak's authorization endpoint with the
// attempt's state, nonce and PKCE challenge.
func (k *Keycloak) AuthorizationURL(attempt sessions.Attempt) string {
	return k.oauth.AuthCodeURL(attempt.State, oauth2.S256ChallengeOption(attempt.Verifier), oidc.Nonce(attempt.Nonce))
}

// Exchange exchanges code at Keycloak's token endpoint with the attempt's verifier, and verifies the
// ID token: its signature against the realm's keys with RS256 alone, its issuer, audience and expiry,
// the attempt's nonce, a verified address and Keycloak's login-session identifier. It returns
// signin.ErrFailed when Keycloak refuses the code or the ID token does not hold, and any other error
// when Keycloak, its keys or the client's secret cannot be reached.
func (k *Keycloak) Exchange(ctx context.Context, code string, attempt sessions.Attempt) (signin.Assertion, error) {
	secret, err := os.ReadFile(k.secretFile)
	if err != nil {
		return signin.Assertion{}, fmt.Errorf("the secret of the client: %w", err)
	}
	config := k.oauth
	config.ClientSecret = strings.TrimRight(string(secret), "\r\n")
	ctx = context.WithValue(ctx, oauth2.HTTPClient, k.client)
	token, err := config.Exchange(ctx, code, oauth2.VerifierOption(attempt.Verifier))
	if err != nil {
		var refused *oauth2.RetrieveError
		if errors.As(err, &refused) && refused.Response != nil && refused.Response.StatusCode < http.StatusInternalServerError {
			return signin.Assertion{}, fmt.Errorf("%w: Keycloak refused the code: %s", signin.ErrFailed, refused.ErrorCode)
		}
		return signin.Assertion{}, fmt.Errorf("the code exchange: %w", err)
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		return signin.Assertion{}, fmt.Errorf("%w: Keycloak's answer holds no ID token", signin.ErrFailed)
	}
	var unreachable error
	verified, err := k.verifier.Verify(withKeyFailure(ctx, &unreachable), raw)
	if unreachable != nil {
		return signin.Assertion{}, fmt.Errorf("the realm's keys: %w", unreachable)
	}
	if err != nil {
		return signin.Assertion{}, fmt.Errorf("%w: the ID token: %v", signin.ErrFailed, err)
	}
	if verified.Nonce != attempt.Nonce {
		return signin.Assertion{}, fmt.Errorf("%w: the ID token's nonce is not the attempt's", signin.ErrFailed)
	}
	var claims struct {
		Address      string `json:"email"`
		Verified     bool   `json:"email_verified"`
		Name         string `json:"name"`
		LoginSession string `json:"sid"`
	}
	if err := verified.Claims(&claims); err != nil {
		return signin.Assertion{}, fmt.Errorf("%w: the ID token's claims: %v", signin.ErrFailed, err)
	}
	if claims.Address == "" || !claims.Verified {
		return signin.Assertion{}, fmt.Errorf("%w: the ID token holds no verified address", signin.ErrFailed)
	}
	if claims.LoginSession == "" {
		return signin.Assertion{}, fmt.Errorf("%w: the ID token names no login session", signin.ErrFailed)
	}
	return signin.Assertion{
		Subject:      principals.Subject{Issuer: verified.Issuer, Subject: verified.Subject},
		Address:      claims.Address,
		Name:         claims.Name,
		LoginSession: claims.LoginSession,
	}, nil
}

// keySet holds the realm's keys, which it fetches from Keycloak's keys endpoint on first use and again
// for a key that it does not hold, and verifies an ID token's signature against them. go-oidc reports
// every failure of a key set alike, so a fetch that fails is also recorded in the request's context,
// where Exchange tells a Keycloak that cannot be reached from a token that does not verify.
type keySet struct {
	url    string
	client *http.Client
	mu     sync.Mutex
	keys   jose.JSONWebKeySet
}

// VerifySignature verifies raw's signature with RS256 and returns its payload.
func (s *keySet) VerifySignature(ctx context.Context, raw string) ([]byte, error) {
	signed, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, err
	}
	if len(signed.Signatures) != 1 {
		return nil, errors.New("the token has more than one signature")
	}
	key, err := s.key(ctx, signed.Signatures[0].Header.KeyID)
	if err != nil {
		return nil, err
	}
	return signed.Verify(key)
}

// key returns the key that kid names, and fetches the keys again when it does not hold that one.
func (s *keySet) key(ctx context.Context, kid string) (*jose.JSONWebKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if found := s.keys.Key(kid); len(found) > 0 {
		return &found[0], nil
	}
	keys, err := s.fetch(ctx)
	if err != nil {
		recordKeyFailure(ctx, err)
		return nil, err
	}
	s.keys = keys
	if found := s.keys.Key(kid); len(found) > 0 {
		return &found[0], nil
	}
	return nil, fmt.Errorf("the realm has no key %q", kid)
}

func (s *keySet) fetch(ctx context.Context) (jose.JSONWebKeySet, error) {
	var keys jose.JSONWebKeySet
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return keys, err
	}
	answer, err := s.client.Do(request)
	if err != nil {
		return keys, err
	}
	defer answer.Body.Close()
	if answer.StatusCode != http.StatusOK {
		return keys, fmt.Errorf("the keys endpoint answered %s", answer.Status)
	}
	return keys, json.NewDecoder(answer.Body).Decode(&keys)
}

// keyFailure is the context key under which Exchange receives the failure of a key fetch.
type keyFailure struct{}

func withKeyFailure(ctx context.Context, failure *error) context.Context {
	return context.WithValue(ctx, keyFailure{}, failure)
}

func recordKeyFailure(ctx context.Context, err error) {
	if failure, ok := ctx.Value(keyFailure{}).(*error); ok {
		*failure = err
	}
}
