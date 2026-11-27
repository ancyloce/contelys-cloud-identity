//go:build scenario

package scenario

import (
	"encoding/json"
	"net/http"
	"testing"
)

// The harness runs Keycloak at the test baseline, with a certificate for the name keycloak from the
// run's certificate authority, and with the public issuer on the authentication hostname that design
// section 09 sets. The scenarios of sign-in and of the realm build on it.
func TestTheHarnessRunsKeycloakAtTheTestBaseline(t *testing.T) {
	status, body := startKeycloak(t).do(t, http.MethodGet, "/realms/master/.well-known/openid-configuration", "", nil)
	var configuration struct {
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal(body, &configuration); err != nil {
		t.Fatalf("Keycloak answered %d: %v", status, err)
	}
	if want := "https://" + authenticationHostname + "/realms/master"; configuration.Issuer != want {
		t.Errorf("Keycloak's issuer is %q, want %q", configuration.Issuer, want)
	}
}
