//go:build scenario

package scenario

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ancyloce/contelys-cloud-libs-service/tokens"
)

// A person with a Keycloak account signs in through Identity, and the next request of their browser is
// admitted: Edge receives an internal token and the limit key in place of the cookie, and a domain
// service verifies the token with the shared library alone, against Identity's key set, and refuses it
// once it is altered or has expired (design sections 04 and 05, I09 for internal tokens).
func TestABrowserSignsInAndIsAdmitted(t *testing.T) {
	k, instance := signInEnvironment(t)
	address, password := k.person(t)

	started := instance.startSignIn(t, "/projects/42")
	authorization, err := url.Parse(started.location)
	if err != nil {
		t.Fatal(err)
	}
	if want := "https://" + authenticationHostname + "/realms/" + realmName + "/protocol/openid-connect/auth"; authorization.Scheme+"://"+authorization.Host+authorization.Path != want {
		t.Errorf("the sign-in redirects to %s, want Keycloak's authorization endpoint %s", started.location, want)
	}
	query := authorization.Query()
	for parameter, want := range map[string]string{
		"client_id": identityClientID, "redirect_uri": callbackURL, "response_type": "code", "code_challenge_method": "S256",
	} {
		if got := query.Get(parameter); got != want {
			t.Errorf("the authorization request's %s is %q, want %q", parameter, got, want)
		}
	}
	for _, parameter := range []string{"state", "nonce", "code_challenge"} {
		if query.Get(parameter) == "" {
			t.Errorf("the authorization request has no %s", parameter)
		}
	}
	expectCookie(t, started.cookie, http.SameSiteLaxMode)

	callback := k.authorize(t, started.location, address, password)
	completed := instance.complete(t, callback, started.cookie.Value)
	if completed.answer.StatusCode != http.StatusFound || completed.answer.Header.Get("Location") != "/projects/42" {
		t.Fatalf("the callback answered %d, Location %q, %s; want 302 to /projects/42",
			completed.answer.StatusCode, completed.answer.Header.Get("Location"), completed.body)
	}
	if completed.session == nil {
		t.Fatal("the callback set no session cookie")
	}
	expectCookie(t, completed.session, http.SameSiteStrictMode)
	if cleared := findCookie(completed.answer, signInCookie); cleared == nil || cleared.MaxAge >= 0 {
		t.Errorf("the callback leaves the cookie %s in place: %v", signInCookie, cleared)
	}
	if completed.answer.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("the callback's answer may be cached: Cache-Control %q", completed.answer.Header.Get("Cache-Control"))
	}

	recipient := instance.recipient(t)
	var firstToken string
	var issued time.Time
	var limitKey string
	for i := range 2 {
		requestID, admitted, body := instance.authenticate(t, completed.session.Value)
		if admitted.StatusCode != http.StatusOK {
			t.Fatalf("the admission answered %d %s, want 200", admitted.StatusCode, body)
		}
		if admitted.Header.Get("Cookie") != "" || admitted.Header.Get("Set-Cookie") != "" || len(body) != 0 {
			t.Errorf("the admitted answer carries a cookie or a body: %v %q", admitted.Header, body)
		}
		key := admitted.Header.Get("X-Contelys-Limit-Key")
		if !regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`).MatchString(key) || (limitKey != "" && key != limitKey) {
			t.Errorf("the admission's limit key is %q, want one of 1 to 64 characters that never changes", key)
		}
		limitKey = key
		token, found := strings.CutPrefix(admitted.Header.Get("Authorization"), "Bearer ")
		if !found {
			t.Fatalf("the admission's Authorization is %q", admitted.Header.Get("Authorization"))
		}
		claims, err := recipient.Internal(context.Background(), token)
		if err != nil {
			t.Fatalf("the recipient refuses the internal token: %v", err)
		}
		if claims.Principal == "" || claims.Session == "" || claims.AuthorityVersion != 1 || claims.RequestID != requestID {
			t.Errorf("the internal token says %+v, want a principal, a session, authority version 1 and the request ID %s", claims, requestID)
		}
		if claims.Session == completed.session.Value {
			t.Error("the internal token's sid is the cookie's value")
		}
		if i == 0 {
			firstToken, issued = token, time.Now()
		}
	}

	for _, altered := range alter(firstToken) {
		if _, err := recipient.Internal(context.Background(), altered); !errors.Is(err, tokens.ErrInvalid) {
			t.Errorf("the recipient takes an altered token: %v", err)
		}
	}

	if kid := keyID(t, firstToken); !slices.Contains(instance.keySet(t), kid) {
		t.Errorf("the key set does not publish the key %s that signs internal tokens", kid)
	}

	// The token is valid for 60 seconds, and the library allows five seconds of difference between clocks.
	time.Sleep(time.Until(issued.Add(66 * time.Second)))
	if _, err := recipient.Internal(context.Background(), firstToken); !errors.Is(err, tokens.ErrInvalid) {
		t.Errorf("the recipient takes an expired token: %v", err)
	}
}

// I05: a callback with the state of another browser's attempt gives no session and leaves that
// attempt to its own browser, and an attempt that was completed once gives no second session (design
// section 04).
func TestACallbackWithTheStateOfAnotherBrowserOrUsedTwiceGivesNoSession(t *testing.T) {
	k, instance := signInEnvironment(t)
	address, password := k.person(t)
	victim := instance.startSignIn(t, "/")
	attacker := instance.startSignIn(t, "/")
	callback := k.authorize(t, attacker.location, address, password)

	for _, attempt := range []struct {
		name, cookie string
		admitted     bool
	}{
		{"with the cookie of another browser", victim.cookie.Value, false},
		{"with the cookie of its own browser", attacker.cookie.Value, true},
		{"a second time", attacker.cookie.Value, false},
	} {
		completed := instance.complete(t, callback, attempt.cookie)
		if attempt.admitted != (completed.session != nil) || attempt.admitted != (completed.answer.StatusCode == http.StatusFound) {
			t.Errorf("the callback %s answered %d with session cookie %t, want a session %t",
				attempt.name, completed.answer.StatusCode, completed.session != nil, attempt.admitted)
		}
		if !attempt.admitted && problemCode(completed.body) != "sign_in_failed" {
			t.Errorf("the callback %s answered %s, want sign_in_failed", attempt.name, completed.body)
		}
		// Only a completed sign-in clears the attempt's cookie, so a forged callback that fails in a
		// browser leaves that browser's own attempt alone.
		if cleared := findCookie(completed.answer, signInCookie); !attempt.admitted && cleared != nil {
			t.Errorf("the failed callback %s sets the cookie %s", attempt.name, cleared)
		}
	}
}

// I04: callbacks for the same subject that arrive at the same time give one principal, which every
// session admits with the same identifier and limit key (design section 04). Eight callbacks make the
// first sign-ins of one subject race in Identity.
func TestTwoCallbacksForTheSameSubjectGiveOnePrincipal(t *testing.T) {
	const callbacks = 8
	k, instance := signInEnvironment(t)
	address, password := k.person(t)
	var attempts []signInStart
	var returned []*url.URL
	for range callbacks {
		started := instance.startSignIn(t, "/")
		attempts = append(attempts, started)
		returned = append(returned, k.authorize(t, started.location, address, password))
	}

	completed := make([]signInCompletion, callbacks)
	var together sync.WaitGroup
	for i := range attempts {
		together.Go(func() { completed[i] = instance.complete(t, returned[i], attempts[i].cookie.Value) })
	}
	together.Wait()

	recipient := instance.recipient(t)
	principals, limitKeys, sessions := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i, done := range completed {
		if done.session == nil {
			t.Fatalf("callback %d answered %d %s without a session", i+1, done.answer.StatusCode, done.body)
		}
		_, admitted, body := instance.authenticate(t, done.session.Value)
		token, _ := strings.CutPrefix(admitted.Header.Get("Authorization"), "Bearer ")
		claims, err := recipient.Internal(context.Background(), token)
		if admitted.StatusCode != http.StatusOK || err != nil {
			t.Fatalf("session %d: the admission answered %d %s: %v", i+1, admitted.StatusCode, body, err)
		}
		principals[claims.Principal] = true
		sessions[claims.Session] = true
		limitKeys[admitted.Header.Get("X-Contelys-Limit-Key")] = true
	}
	if len(principals) != 1 || len(limitKeys) != 1 {
		t.Errorf("%d sign-ins of one subject give %d principals with %d limit keys, want one", callbacks, len(principals), len(limitKeys))
	}
	if len(sessions) != callbacks {
		t.Errorf("%d sign-ins give %d sessions, want one each", callbacks, len(sessions))
	}
}

// A sign-in returns only to a path of the application origin, so that no link can send a person who
// signs in to another site (design section 04).
func TestASignInReturnsOnlyToAPathOfTheApplication(t *testing.T) {
	instance := startIdentity(t, newInputs(t, sharedPostgres.create(t)))
	instance.becomesReady(t, "before the sign-ins")
	for _, path := range []string{"https://elsewhere.example.test/", "//elsewhere.example.test/", "/\\elsewhere.example.test", "relative"} {
		answer, body := instance.do(t, http.MethodGet, "/api/identity/v1/session/sign-in?returnTo="+url.QueryEscape(path), nil, nil)
		if answer.StatusCode != http.StatusBadRequest || problemCode(body) != "invalid_return_path" || findCookie(answer, signInCookie) != nil {
			t.Errorf("a sign-in that returns to %q answered %d %s, want 400 invalid_return_path and no attempt", path, answer.StatusCode, body)
		}
	}
}

// signInEnvironment is an Identity instance that is ready and signs browsers in through the run's
// Keycloak, as the realm's client identity.
func signInEnvironment(t *testing.T) (*keycloak, *identity) {
	t.Helper()
	k := startKeycloak(t)
	in := newInputs(t, sharedPostgres.create(t))
	in.write(t, keycloakSecret, []byte(k.identitySecret))
	instance := startIdentity(t, in)
	instance.becomesReady(t, "before the sign-in")
	return k, instance
}

// person creates an account of the realm with a password, as the test fixture does (Q12 of the plan).
func (k *keycloak) person(t *testing.T) (address, password string) {
	t.Helper()
	address = "person-" + strings.ToLower(rand.Text()) + "@example.test"
	password = "a long password of a person " + strings.ToLower(rand.Text())
	k.createAccount(t, address, map[string]any{
		"credentials": []map[string]any{{"type": "password", "value": password, "temporary": false}},
	})
	return address, password
}

// signInStart is a browser's start of a sign-in at Identity: where Identity redirects it, and the
// cookie that binds the attempt to it.
type signInStart struct {
	location string
	cookie   *http.Cookie
}

// startSignIn opens Identity's sign-in route, as a browser does through Edge.
func (i *identity) startSignIn(t *testing.T, returnTo string) signInStart {
	t.Helper()
	answer, body := i.do(t, http.MethodGet, "/api/identity/v1/session/sign-in?returnTo="+url.QueryEscape(returnTo), nil, nil)
	cookie := findCookie(answer, signInCookie)
	if answer.StatusCode != http.StatusFound || cookie == nil || answer.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("the sign-in answered %d, Cache-Control %q, %s; want 302 with the cookie %s",
			answer.StatusCode, answer.Header.Get("Cache-Control"), body, signInCookie)
	}
	return signInStart{location: answer.Header.Get("Location"), cookie: cookie}
}

// signInCompletion is Identity's answer to a callback, with the session cookie that it set, if any.
type signInCompletion struct {
	answer  *http.Response
	body    []byte
	session *http.Cookie
}

// complete brings Keycloak's callback to Identity, as the browser does through Edge, with the value of
// the browser's attempt cookie.
func (i *identity) complete(t *testing.T, callback *url.URL, cookie string) signInCompletion {
	t.Helper()
	header := http.Header{"Cookie": {signInCookie + "=" + cookie}}
	answer, body := i.do(t, http.MethodGet, callback.Path+"?"+callback.RawQuery, header, nil)
	return signInCompletion{answer: answer, body: body, session: findCookie(answer, sessionCookie)}
}

// recipient is a domain service that verifies internal tokens with the shared library against
// Identity's key set.
func (i *identity) recipient(t *testing.T) *tokens.Verifier {
	t.Helper()
	return tokens.New(tokens.Options{
		KeySet:     i.url(t, "/internal/v1/keys"),
		Client:     &http.Client{Transport: &http.Transport{TLSClientConfig: trust(identityName)}, Timeout: 10 * time.Second},
		Deployable: "projects",
	})
}

// keySet lists the key IDs of Identity's key set, which any caller reads without a token.
func (i *identity) keySet(t *testing.T) []string {
	t.Helper()
	answer, body := i.do(t, http.MethodGet, "/internal/v1/keys", nil, nil)
	var set struct {
		Keys []struct{ Kid, Kty, Crv, Alg, Use, X string }
	}
	if answer.StatusCode != http.StatusOK || json.Unmarshal(body, &set) != nil {
		t.Fatalf("the key set answered %d %s", answer.StatusCode, body)
	}
	var ids []string
	for _, key := range set.Keys {
		if key.Kty != "OKP" || key.Crv != "Ed25519" || key.Alg != "EdDSA" || key.Use != "sig" || len(key.X) != 43 {
			t.Errorf("the key set holds %+v, want an Ed25519 key of RFC 8037", key)
		}
		ids = append(ids, key.Kid)
	}
	return ids
}

// keyID is the kid of a token's header.
func keyID(t *testing.T, token string) string {
	t.Helper()
	header, _, _ := strings.Cut(token, ".")
	decoded, err := base64.RawURLEncoding.DecodeString(header)
	var parsed struct{ Kid string }
	if err != nil || json.Unmarshal(decoded, &parsed) != nil {
		t.Fatalf("the token's header %q: %v", header, err)
	}
	return parsed.Kid
}

// alter returns copies of token with one character changed in its payload and in its signature.
func alter(token string) []string {
	parts := strings.Split(token, ".")
	var altered []string
	for _, part := range []int{1, 2} {
		changed := slices.Clone(parts)
		middle := []byte(changed[part])
		position := len(middle) / 2
		if middle[position] == 'A' {
			middle[position] = 'B'
		} else {
			middle[position] = 'A'
		}
		changed[part] = string(middle)
		altered = append(altered, strings.Join(changed, "."))
	}
	return altered
}

// expectCookie checks that cookie has the attributes of design section 04: Secure, HttpOnly, the path
// / without a domain, which the prefix __Host- requires, and sameSite.
func expectCookie(t *testing.T, cookie *http.Cookie, sameSite http.SameSite) {
	t.Helper()
	if !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.Domain != "" || cookie.SameSite != sameSite {
		t.Errorf("the cookie %s is %s, want Secure, HttpOnly, Path=/, no Domain and SameSite %v", cookie.Name, cookie, sameSite)
	}
}

// findCookie is the cookie name that answer sets, or nil.
func findCookie(answer *http.Response, name string) *http.Cookie {
	for _, cookie := range answer.Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

// problemCode is the code of a problem body.
func problemCode(body []byte) string {
	var problem struct{ Code string }
	_ = json.Unmarshal(body, &problem)
	return problem.Code
}
