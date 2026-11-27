//go:build scenario

package scenario

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// The harness applied the realm once when Keycloak started. Running the same play again changes
// nothing, so an installation can run it on every deployment (Identity ADR 0001).
func TestASecondRunOfThePlayChangesNothing(t *testing.T) {
	k := startKeycloak(t)
	if run := k.mustApply(t); run.changed != 0 {
		t.Errorf("the second run changed %d tasks, want none\n%s", run.changed, run.output)
	}
}

// Every setting of design section 09 that the Identity team owns reads back from Keycloak as the
// design gives it.
func TestTheRealmHoldsTheSettingsOfDesignSection09(t *testing.T) {
	k := startKeycloak(t)

	var settings map[string]any
	k.admin(t, "", &settings)
	expectSettings(t, "the realm", settings, map[string]any{
		"enabled":                             true,
		"registrationAllowed":                 false,
		"resetPasswordAllowed":                true,
		"registrationEmailAsUsername":         true,
		"loginWithEmailAllowed":               true,
		"duplicateEmailsAllowed":              false,
		"editUsernameAllowed":                 false,
		"rememberMe":                          false,
		"bruteForceProtected":                 true,
		"passwordPolicy":                      "length(15) and maxLength(128) and notUsername and notEmail and passwordBlacklist(" + passwordList + ")",
		"loginTheme":                          loginTheme,
		"emailTheme":                          loginTheme,
		"accessTokenLifespan":                 float64(60),
		"actionTokenGeneratedByAdminLifespan": float64(43200),
		"smtpServer": map[string]any{
			"host": "mailpit", "port": "1025", "from": "identity@example.test", "ssl": "false", "starttls": "false", "auth": "false",
		},
	})

	var providers []any
	k.admin(t, "/identity-provider/instances", &providers)
	if len(providers) != 0 {
		t.Errorf("the realm has %d identity providers, want none (design section 14)", len(providers))
	}

	var roles []struct{ Name string }
	k.admin(t, "/roles", &roles)
	if diff := cmp.Diff([]string{"default-roles-" + realmName, "offline_access", "uma_authorization"}, sortedNames(roles)); diff != "" {
		t.Errorf("the realm's roles, beyond Keycloak's defaults (-want +got):\n%s", diff)
	}

	var profile struct {
		Attributes []struct {
			Name        string
			Required    *struct{ Roles []string }
			Permissions struct{ View, Edit []string }
		}
	}
	k.admin(t, "/users/profile", &profile)
	var attributes []string
	for _, attribute := range profile.Attributes {
		attributes = append(attributes, attribute.Name)
		switch attribute.Name {
		case "username", "email":
			if !slices.Equal(attribute.Permissions.Edit, []string{"admin"}) {
				t.Errorf("the user profile lets %v edit %s, want the administrator alone", attribute.Permissions.Edit, attribute.Name)
			}
		case "name":
			if attribute.Required == nil || !slices.Equal(attribute.Required.Roles, []string{"user"}) {
				t.Errorf("the user profile's name is required %+v, want of the person, role user", attribute.Required)
			}
		}
	}
	if diff := cmp.Diff([]string{"username", "email", "name"}, attributes); diff != "" {
		t.Errorf("the user profile's attributes (-want +got):\n%s", diff)
	}

	identity := k.realmClient(t, identityClientID)
	expectSettings(t, "the client identity", identity.settings, map[string]any{
		"publicClient":              false,
		"clientAuthenticatorType":   "client-secret",
		"standardFlowEnabled":       true,
		"implicitFlowEnabled":       false,
		"directAccessGrantsEnabled": false,
		"serviceAccountsEnabled":    false,
		"frontchannelLogout":        false,
		"fullScopeAllowed":          false,
		"redirectUris":              []any{callbackURL},
		"webOrigins":                []any{},
		"baseUrl":                   applicationOrigin,
	})
	expectSettings(t, "the attributes of the client identity", identity.attributes, map[string]any{
		"pkce.code.challenge.method":                "S256",
		"backchannel.logout.url":                    backChannelLogoutURL,
		"backchannel.logout.session.required":       "true",
		"oauth2.device.authorization.grant.enabled": "false",
		"oidc.ciba.grant.enabled":                   "false",
		"use.refresh.tokens":                        "false",
	})
	if diff := cmp.Diff([]string{"basic", "email"}, identity.defaultScopes); diff != "" {
		t.Errorf("the client identity's default scopes (-want +got):\n%s", diff)
	}
	if len(identity.optionalScopes) != 0 {
		t.Errorf("the client identity has the optional scopes %v, want none", identity.optionalScopes)
	}
	if diff := cmp.Diff(map[string]string{
		"user.attribute": "name", "claim.name": "name", "jsonType.label": "String", "id.token.claim": "true",
		"access.token.claim": "false", "userinfo.token.claim": "false", "introspection.token.claim": "false",
	}, identity.mappers["name"]); diff != "" {
		t.Errorf("the client identity's mapper of the claim name (-want +got):\n%s", diff)
	}
	if identity.secret != k.identitySecret {
		t.Errorf("the client identity's secret is not the one of its file")
	}

	admin := k.realmClient(t, adminClientID)
	expectSettings(t, "the client identity-admin", admin.settings, map[string]any{
		"publicClient":              false,
		"standardFlowEnabled":       false,
		"implicitFlowEnabled":       false,
		"directAccessGrantsEnabled": false,
		"serviceAccountsEnabled":    true,
	})
	if !slices.Contains(admin.defaultScopes, "kc-admin-api") {
		t.Errorf("the client identity-admin's default scopes %v lack kc-admin-api", admin.defaultScopes)
	}
	if admin.secret != k.adminSecret {
		t.Errorf("the client identity-admin's secret is not the one of its file")
	}
	var serviceAccount struct{ ID string }
	k.admin(t, "/clients/"+admin.id+"/service-account-user", &serviceAccount)
	var mappings struct {
		RealmMappings  []struct{ Name string }
		ClientMappings map[string]struct {
			Mappings []struct{ Name string }
		}
	}
	k.admin(t, "/users/"+serviceAccount.ID+"/role-mappings", &mappings)
	clientRoles := map[string][]string{}
	for client, mapped := range mappings.ClientMappings {
		clientRoles[client] = sortedNames(mapped.Mappings)
	}
	if diff := cmp.Diff(map[string][]string{"realm-management": {"manage-users", "view-users"}}, clientRoles); diff != "" {
		t.Errorf("the service account's client roles (-want +got):\n%s", diff)
	}
	if realmRoles := sortedNames(mappings.RealmMappings); len(realmRoles) != 0 {
		t.Errorf("the service account holds the realm roles %v, want none", realmRoles)
	}
}

// The service account reaches the realm's accounts and nothing else of the realm (design section 09):
// it creates an account, and it can neither read the clients nor change the realm.
func TestTheServiceAccountManagesAccountsAndNothingElse(t *testing.T) {
	k := startKeycloak(t)
	token := k.token(t, realmName, url.Values{
		"grant_type": {"client_credentials"}, "client_id": {adminClientID}, "client_secret": {k.adminSecret},
	})
	for _, attempt := range []struct {
		name, method, path string
		body               any
		want               int
	}{
		{"create an account", http.MethodPost, "/users", map[string]any{"username": "service-account-test@example.test", "email": "service-account-test@example.test", "enabled": true}, http.StatusCreated},
		{"read the accounts", http.MethodGet, "/users?max=1", nil, http.StatusOK},
		{"read the clients", http.MethodGet, "/clients", nil, http.StatusForbidden},
		{"change the realm", http.MethodPut, "", map[string]any{"registrationAllowed": true}, http.StatusForbidden},
	} {
		if status, body := k.do(t, attempt.method, adminAPI+attempt.path, token, attempt.body); status != attempt.want {
			t.Errorf("the service account tried to %s: %d %s, want %d", attempt.name, status, body, attempt.want)
		}
	}
}

// The realm allows neither the implicit flow nor the password grant on any client, Keycloak's own
// among them (design section 04): a password grant with the realm's admin-cli, which Keycloak creates
// with that grant, is refused.
func TestTheRealmAllowsNeitherThePasswordGrantNorTheImplicitFlow(t *testing.T) {
	k := startKeycloak(t)
	var clients []struct {
		ClientID                  string
		ImplicitFlowEnabled       bool
		DirectAccessGrantsEnabled bool
	}
	k.admin(t, "/clients", &clients)
	for _, client := range clients {
		if client.ImplicitFlowEnabled || client.DirectAccessGrantsEnabled {
			t.Errorf("the client %s allows the implicit flow %t, the password grant %t, want neither",
				client.ClientID, client.ImplicitFlowEnabled, client.DirectAccessGrantsEnabled)
		}
	}

	address := "grant-" + strings.ToLower(rand.Text()) + "@example.test"
	password := "a password for no grant " + strings.ToLower(rand.Text())
	k.createAccount(t, address, map[string]any{
		"credentials": []map[string]any{{"type": "password", "value": password, "temporary": false}},
	})
	status, body := k.do(t, http.MethodPost, "/realms/"+realmName+"/protocol/openid-connect/token", "", url.Values{
		"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {address}, "password": {password},
	})
	var refusal struct{ Error string }
	if status == http.StatusOK || json.Unmarshal(body, &refusal) != nil || refusal.Error != "unauthorized_client" {
		t.Errorf("a password grant with admin-cli answered %d %s, want unauthorized_client", status, body)
	}
}

// An installation whose SMTP server requires TLS and a sign-in gets that setting, with the password
// from its file, and a second run of the play with it changes nothing. Implicit TLS is the other way
// that the design allows (design section 09). The run's own setting is restored afterwards, because
// the scenarios share one Keycloak.
func TestTheSMTPSettingOfAnInstallationThatRequiresTLSAndASignIn(t *testing.T) {
	k := startKeycloak(t)
	t.Cleanup(func() { k.mustApply(t) })
	smtpPassword := rand.Text()
	starttls, err := json.Marshal(map[string]any{"smtp": map[string]any{
		"host": "smtp.example.test", "port": 587, "from": "identity@example.test", "tls": "starttls",
		"username": "identity", "password_file": "/inputs/smtp-password",
	}})
	if err != nil {
		t.Fatal(err)
	}
	implicit, err := json.Marshal(map[string]any{"smtp": map[string]any{
		"host": "smtp.example.test", "port": 465, "from": "identity@example.test", "tls": "implicit",
	}})
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{
		"smtp-password": []byte(smtpPassword), "smtp-starttls.json": starttls, "smtp-implicit.json": implicit,
	} {
		if err := k.writeInput(name, content); err != nil {
			t.Fatal(err)
		}
	}
	smtpSetting := func() map[string]any {
		t.Helper()
		var settings map[string]any
		k.admin(t, "", &settings)
		smtp, _ := settings["smtpServer"].(map[string]any)
		return smtp
	}

	k.mustApply(t, "smtp-starttls.json")
	smtp := smtpSetting()
	expectSettings(t, "the SMTP setting with STARTTLS and a sign-in", smtp, map[string]any{
		"host": "smtp.example.test", "port": "587", "from": "identity@example.test",
		"ssl": "false", "starttls": "true", "auth": "true", "user": "identity",
	})
	if password, _ := smtp["password"].(string); password == "" || password == smtpPassword {
		t.Errorf("the SMTP password reads back as %q, want it set and masked", password)
	}
	if run := k.mustApply(t, "smtp-starttls.json"); run.changed != 0 {
		t.Errorf("the second run with the sign-in changed %d tasks, want none\n%s", run.changed, run.output)
	}

	k.mustApply(t, "smtp-implicit.json")
	expectSettings(t, "the SMTP setting with implicit TLS", smtpSetting(), map[string]any{
		"host": "smtp.example.test", "port": "465", "ssl": "true", "starttls": "false", "auth": "false",
	})
}

// A person who must set a new password sees "Sign out from other devices" checked, so that a reset
// ends their other sessions unless they uncheck it (design sections 04 and 09). Keycloak's own theme
// leaves the box unchecked.
func TestTheLoginThemeChecksSignOutFromOtherDevices(t *testing.T) {
	k := startKeycloak(t)
	address := "theme-" + strings.ToLower(rand.Text()) + "@example.test"
	password := "a temporary password " + strings.ToLower(rand.Text())
	k.createAccount(t, address, map[string]any{
		"credentials": []map[string]any{{"type": "password", "value": password, "temporary": true}},
	})

	page := k.signIn(t, address, password)
	box := regexp.MustCompile(`<input[^>]*name="logout-sessions"[^>]*>`).FindString(page)
	if box == "" {
		t.Fatalf("the page after the sign-in shows no box logout-sessions:\n%s", page)
	}
	if !strings.Contains(box, "checked") {
		t.Errorf("the box is %s, want it checked", box)
	}
}

// Keycloak reads the list of common and breached passwords from the file that the deployment mounts
// into data/password-blacklists/, and refuses a password that the list holds (design section 09).
func TestTheRealmRefusesAPasswordOfTheList(t *testing.T) {
	k := startKeycloak(t)
	list, err := os.ReadFile(k.passwordListFile())
	if err != nil {
		t.Fatal(err)
	}
	listed, _, _ := strings.Cut(string(list), "\n")
	id := k.createAccount(t, "list-"+strings.ToLower(rand.Text())+"@example.test", nil)

	for _, attempt := range []struct {
		password string
		want     int
	}{
		{listed, http.StatusBadRequest},
		{"not on the list " + strings.ToLower(rand.Text()), http.StatusNoContent},
	} {
		status, body := k.do(t, http.MethodPut, adminAPI+"/users/"+id+"/reset-password", k.adminToken(t),
			map[string]any{"type": "password", "value": attempt.password, "temporary": false})
		if status != attempt.want {
			t.Errorf("setting the password %q: %d %s, want %d", attempt.password, status, body, attempt.want)
		}
		if attempt.want == http.StatusBadRequest && !strings.Contains(string(body), "Blacklisted") {
			t.Errorf("the refusal %s does not name the list", body)
		}
	}
}

// mustApply runs the play with the overrides and fails the scenario unless it ran without a failure.
func (k *keycloak) mustApply(t *testing.T, overrides ...string) play {
	t.Helper()
	run, err := k.applyRealm(overrides...)
	if err != nil {
		t.Fatal(err)
	}
	if run.failed != 0 || run.ok == 0 {
		t.Fatalf("the play with %v: ok=%d failed=%d\n%s", overrides, run.ok, run.failed, run.output)
	}
	return run
}

// expectSettings compares each setting of want with the one of got.
func expectSettings(t *testing.T, of string, got, want map[string]any) {
	t.Helper()
	for setting, value := range want {
		if diff := cmp.Diff(value, got[setting]); diff != "" {
			t.Errorf("%s: %s (-want +got):\n%s", of, setting, diff)
		}
	}
}

// sortedNames lists the names of roles, sorted.
func sortedNames(roles []struct{ Name string }) []string {
	var names []string
	for _, role := range roles {
		names = append(names, role.Name)
	}
	slices.Sort(names)
	return names
}
