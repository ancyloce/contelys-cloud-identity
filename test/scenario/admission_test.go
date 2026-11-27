//go:build scenario

package scenario

import (
	"crypto/rand"
	"net/http"
	"testing"
)

// I06: a request without a session cookie, or with a cookie that is no session's value, gets 401 with
// WWW-Authenticate: Session, which Edge returns to the browser (design section 05).
func TestARequestWithoutASessionGets401(t *testing.T) {
	instance := startIdentity(t, newInputs(t, sharedPostgres.create(t)))
	instance.becomesReady(t, "before Edge's calls")

	for _, c := range []struct{ name, cookie string }{
		{"without a cookie", ""},
		{"with a cookie that is no session's", rand.Text() + rand.Text()},
	} {
		_, answer, body := instance.authenticate(t, c.cookie)
		if answer.StatusCode != http.StatusUnauthorized || answer.Header.Get("WWW-Authenticate") != "Session" || problemCode(body) != "session_required" {
			t.Errorf("%s: %d, WWW-Authenticate %q, %s; want 401, Session and session_required",
				c.name, answer.StatusCode, answer.Header.Get("WWW-Authenticate"), body)
		}
		if answer.Header.Get("Authorization") != "" {
			t.Errorf("%s: the refusal carries an Authorization header", c.name)
		}
	}
}
