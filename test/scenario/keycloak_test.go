//go:build scenario

package scenario

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// The application realm as realm/realm.yaml defines it, and what the scenarios give the play as an
// installation would.
const (
	realmName            = "contelys"
	identityClientID     = "identity"
	adminClientID        = "identity-admin"
	loginTheme           = "contelys"
	passwordList         = "common-passwords.txt"
	applicationOrigin    = "https://app.example.test"
	callbackURL          = applicationOrigin + "/api/identity/v1/session/callback"
	backChannelLogoutURL = "https://edge:9444/identity/internal/v1/back-channel-logout"
	// adminAPI is the path of the application realm in Keycloak's Admin API.
	adminAPI = "/admin/realms/" + realmName
	// keycloakName is the name that Keycloak's certificate carries, and its alias on the run's network.
	keycloakName = "keycloak"
	// keycloakAdmin is the master realm's administrator, whom the play signs in as.
	keycloakAdmin = "admin"
	// ansibleImage is the image that test/scenario/ansible/ builds, which applies realm/.
	ansibleImage = "contelys/identity-scenario-ansible"
)

// keycloak is the run's Keycloak, at the alias keycloak on the run's network, with the realm applied.
type keycloak struct {
	container *testcontainers.DockerContainer
	// realmDir is the directory realm/ of this project, which the play and the mounts come from.
	realmDir string
	// adminPassword is the password of the master realm's administrator.
	adminPassword string
	// inputs holds what the play reads: its variables, the secrets and the trust store.
	inputs string
	// identitySecret and adminSecret are the secrets of the clients identity and identity-admin.
	identitySecret, adminSecret string
}

var (
	keycloakOnce    sync.Once
	keycloakRunning *keycloak
	keycloakErr     error
)

// startKeycloak starts the run's Keycloak at the test baseline the first time a scenario needs it,
// with the hostname settings of design section 09 and a certificate for the name keycloak from the
// run's certificate authority, and applies the realm once with the play (Q11 of the plan). The login
// theme and the list of passwords are mounted from realm/, as the platform team's deployment mounts
// them. Keycloak's database is its own development file, because the realm is all that the scenarios
// need of it.
func startKeycloak(t *testing.T) *keycloak {
	t.Helper()
	keycloakOnce.Do(func() {
		// A scenario that fails inside the start ends the Once without a result, and the next
		// scenario then reads this error.
		keycloakErr = errors.New("the start of Keycloak ended in an earlier scenario")
		keycloakRunning, keycloakErr = launchKeycloak(t)
	})
	if keycloakErr != nil {
		t.Fatalf("start Keycloak: %v", keycloakErr)
	}
	return keycloakRunning
}

func launchKeycloak(t *testing.T) (*keycloak, error) {
	realmDir, err := filepath.Abs("../../realm")
	if err != nil {
		return nil, err
	}
	// The directory outlives the scenario that first needs Keycloak, so it is not t.TempDir.
	dir, err := os.MkdirTemp("", "identity-keycloak-")
	if err != nil {
		return nil, err
	}
	leftovers.dir = dir
	k := &keycloak{
		realmDir:       realmDir,
		adminPassword:  rand.Text(),
		inputs:         filepath.Join(dir, "inputs"),
		identitySecret: rand.Text(),
		adminSecret:    rand.Text(),
	}
	certificate, key, _ := ca.Issue(t, keycloakName)
	variables, err := json.Marshal(map[string]any{
		"keycloak_url":                 "https://" + keycloakName + ":8443",
		"keycloak_admin_username":      keycloakAdmin,
		"keycloak_admin_password_file": "/inputs/admin-password",
		"application_origin":           applicationOrigin,
		"back_channel_logout_url":      backChannelLogoutURL,
		"identity_client_secret_file":  "/inputs/identity-client-secret",
		"admin_client_secret_file":     "/inputs/admin-client-secret",
		"smtp":                         map[string]any{"host": "mailpit", "port": 1025, "from": "identity@example.test", "tls": "plain"},
	})
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(dir, "tls"), 0o755); err != nil {
		return nil, err
	}
	for name, content := range map[string][]byte{"tls/keycloak.crt": certificate, "tls/keycloak.key": key} {
		if err := writeReadable(filepath.Join(dir, name), content); err != nil {
			return nil, err
		}
	}
	for name, content := range map[string][]byte{
		"ca.crt":                 ca.PEM,
		"variables.json":         variables,
		"admin-password":         []byte(k.adminPassword),
		"identity-client-secret": []byte(k.identitySecret),
		"admin-client-secret":    []byte(k.adminSecret),
	} {
		if err := k.writeInput(name, content); err != nil {
			return nil, err
		}
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		return nil, err
	}

	const tlsDir = "/opt/keycloak/conf/tls"
	c, err := testcontainers.GenericContainer(context.Background(), testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:          keycloakImage,
			ExposedPorts:   []string{"8443/tcp"},
			Networks:       []string{dockerNetwork.Name},
			NetworkAliases: map[string][]string{dockerNetwork.Name: {keycloakName}},
			Env: map[string]string{
				"KC_BOOTSTRAP_ADMIN_USERNAME": keycloakAdmin,
				"KC_BOOTSTRAP_ADMIN_PASSWORD": k.adminPassword,
			},
			Cmd: []string{"start",
				"--db=dev-file",
				"--hostname=https://" + authenticationHostname,
				"--hostname-backchannel-dynamic=false",
				"--http-enabled=false",
				"--https-certificate-file=" + tlsDir + "/keycloak.crt",
				"--https-certificate-key-file=" + tlsDir + "/keycloak.key",
			},
			HostConfigModifier: func(hc *container.HostConfig) {
				hc.Binds = append(hc.Binds,
					filepath.Join(dir, "tls")+":"+tlsDir+":ro",
					filepath.Join(realmDir, "themes", loginTheme)+":/opt/keycloak/themes/"+loginTheme+":ro",
					k.passwordListFile()+":/opt/keycloak/data/password-blacklists/"+passwordList+":ro",
				)
			},
			WaitingFor: wait.ForLog("Listening on: https://0.0.0.0:8443").WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	if c != nil {
		leftovers.container = c
	}
	if err != nil {
		return nil, fmt.Errorf("%w, and Keycloak wrote:\n%s", err, lastLines(c, 40))
	}
	k.container = c.(*testcontainers.DockerContainer)
	if run, err := k.applyRealm(); err != nil {
		return nil, fmt.Errorf("the first run of the play: %w", err)
	} else if run.failed > 0 {
		return nil, fmt.Errorf("the first run of the play failed:\n%s", run.output)
	}
	return k, nil
}

// passwordListFile is the list of passwords in realm/, which the deployment mounts into Keycloak.
func (k *keycloak) passwordListFile() string {
	return filepath.Join(k.realmDir, "password-blacklists", passwordList)
}

// writeInput writes one file of the play's inputs.
func (k *keycloak) writeInput(name string, content []byte) error {
	if err := os.MkdirAll(k.inputs, 0o755); err != nil {
		return err
	}
	return writeReadable(filepath.Join(k.inputs, name), content)
}

// writeReadable writes a file that Keycloak and the play, which run as users of their own, can read.
func writeReadable(path string, content []byte) error {
	if err := os.WriteFile(path, content, 0o644); err != nil {
		return err
	}
	return os.Chmod(path, 0o644)
}

// play is one run of realm/realm.yaml: the counts of its recap and what it wrote.
type play struct {
	ok, changed, failed int
	output              string
}

var recap = regexp.MustCompile(`(?m)^localhost\s*:\s*ok=(\d+)\s+changed=(\d+)\s+unreachable=(\d+)\s+failed=(\d+)`)

// applyRealm runs realm/realm.yaml from the Ansible image that test/scenario/ansible/ pins, against
// Keycloak's internal address on the run's network, as an installation runs it from the tooling image.
// It gives the play the variables of the run, and then those of each file of overrides among the
// inputs.
func (k *keycloak) applyRealm(overrides ...string) (play, error) {
	command := []string{"ansible-playbook", "-i", "localhost,", "/realm/realm.yaml", "-e", "@/inputs/variables.json"}
	for _, file := range overrides {
		command = append(command, "-e", "@/inputs/"+file)
	}
	ctx := context.Background()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			FromDockerfile: testcontainers.FromDockerfile{Context: "ansible", Repo: ansibleImage, Tag: "scenario", KeepImage: true},
			Networks:       []string{dockerNetwork.Name},
			Cmd:            command,
			// The play verifies Keycloak's certificate against the run's certificate authority.
			Env: map[string]string{"SSL_CERT_FILE": "/inputs/ca.crt"},
			HostConfigModifier: func(hc *container.HostConfig) {
				hc.Binds = append(hc.Binds, k.realmDir+":/realm:ro", k.inputs+":/inputs:ro")
			},
			WaitingFor: wait.ForExit().WithExitTimeout(5 * time.Minute),
		},
		Started: true,
	})
	if c != nil {
		defer func() { _ = testcontainers.TerminateContainer(c) }()
	}
	if err != nil {
		return play{}, err
	}
	run := play{output: output(c)}
	counts := recap.FindStringSubmatch(run.output)
	if counts == nil {
		return run, fmt.Errorf("the play wrote no recap:\n%s", run.output)
	}
	run.ok, _ = strconv.Atoi(counts[1])
	run.changed, _ = strconv.Atoi(counts[2])
	unreachable, _ := strconv.Atoi(counts[3])
	run.failed, _ = strconv.Atoi(counts[4])
	run.failed += unreachable
	return run, nil
}

// endpoint is where this test process reaches Keycloak's HTTPS port.
func (k *keycloak) endpoint(t *testing.T) string {
	t.Helper()
	endpoint, err := k.container.PortEndpoint(context.Background(), "8443/tcp", "https")
	if err != nil {
		t.Fatal(err)
	}
	return endpoint
}

// do sends a request to Keycloak from this test process, over TLS for the name keycloak, with body as
// JSON or, when it is url.Values, as a form, and returns the answer's status and body. The request
// names the host keycloak:8443, as a container on the run's network reaches it, because on the test
// baseline Keycloak answers 421 to the host localhost of the mapped port, while it answers the hosts
// keycloak and auth.example.test over the same handshake.
func (k *keycloak) do(t *testing.T, method, path, token string, body any) (int, []byte) {
	t.Helper()
	var content io.Reader
	contentType := ""
	switch b := body.(type) {
	case nil:
	case url.Values:
		content, contentType = bytes.NewBufferString(b.Encode()), "application/x-www-form-urlencoded"
	default:
		encoded, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		content, contentType = bytes.NewReader(encoded), "application/json"
	}
	request, err := http.NewRequest(method, k.endpoint(t)+path, content)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = keycloakName + ":8443"
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: trust(keycloakName)}, Timeout: 20 * time.Second}
	answer, err := client.Do(request)
	if err != nil {
		t.Fatalf("%s %s at Keycloak: %v", method, path, err)
	}
	defer answer.Body.Close()
	answered, err := io.ReadAll(answer.Body)
	if err != nil {
		t.Fatal(err)
	}
	return answer.StatusCode, answered
}

// token asks the token endpoint of the realm named of for an access token with form.
func (k *keycloak) token(t *testing.T, of string, form url.Values) string {
	t.Helper()
	status, body := k.do(t, http.MethodPost, "/realms/"+of+"/protocol/openid-connect/token", "", form)
	var answer struct {
		AccessToken string `json:"access_token"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &answer) != nil || answer.AccessToken == "" {
		t.Fatalf("a token of the realm %s answered %d %s", of, status, body)
	}
	return answer.AccessToken
}

// adminToken is a token of the master realm's administrator.
func (k *keycloak) adminToken(t *testing.T) string {
	t.Helper()
	return k.token(t, "master", url.Values{
		"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {keycloakAdmin}, "password": {k.adminPassword},
	})
}

// admin reads path of the application realm's Admin API as the administrator, into v.
func (k *keycloak) admin(t *testing.T, path string, v any) {
	t.Helper()
	status, body := k.do(t, http.MethodGet, adminAPI+path, k.adminToken(t), nil)
	if status != http.StatusOK {
		t.Fatalf("GET %s%s answered %d %s", adminAPI, path, status, body)
	}
	if err := json.Unmarshal(body, v); err != nil {
		t.Fatalf("GET %s%s: %v", adminAPI, path, err)
	}
}

// realmClient is one client of the application realm, as the Admin API reads it.
type realmClient struct {
	id string
	// settings is the client's representation, and attributes its attributes.
	settings   map[string]any
	attributes map[string]any
	// defaultScopes and optionalScopes name its client scopes, sorted.
	defaultScopes, optionalScopes []string
	// mappers holds the configuration of each protocol mapper, by its name.
	mappers map[string]map[string]string
	secret  string
}

// realmClient reads the client clientID of the application realm as the administrator.
func (k *keycloak) realmClient(t *testing.T, clientID string) realmClient {
	t.Helper()
	var found []map[string]any
	k.admin(t, "/clients?clientId="+url.QueryEscape(clientID), &found)
	if len(found) != 1 {
		t.Fatalf("the realm has %d clients %s, want one", len(found), clientID)
	}
	c := realmClient{settings: found[0], mappers: map[string]map[string]string{}}
	c.id, _ = found[0]["id"].(string)
	c.attributes, _ = found[0]["attributes"].(map[string]any)
	mappers, _ := found[0]["protocolMappers"].([]any)
	for _, m := range mappers {
		mapper, _ := m.(map[string]any)
		name, _ := mapper["name"].(string)
		config, _ := mapper["config"].(map[string]any)
		c.mappers[name] = map[string]string{}
		for key, value := range config {
			c.mappers[name][key], _ = value.(string)
		}
	}
	for kind, scopes := range map[string]*[]string{"default": &c.defaultScopes, "optional": &c.optionalScopes} {
		var listed []struct{ Name string }
		k.admin(t, "/clients/"+c.id+"/"+kind+"-client-scopes", &listed)
		*scopes = sortedNames(listed)
	}
	var secret struct{ Value string }
	k.admin(t, "/clients/"+c.id+"/client-secret", &secret)
	c.secret = secret.Value
	return c
}

// createAccount creates a verified account of the application realm for address, with a name and the
// further settings of extra, and returns its identifier.
func (k *keycloak) createAccount(t *testing.T, address string, extra map[string]any) string {
	t.Helper()
	account := map[string]any{
		"username": address, "email": address, "enabled": true, "emailVerified": true,
		"attributes": map[string][]string{"name": {"A Person"}},
	}
	for key, value := range extra {
		account[key] = value
	}
	if status, body := k.do(t, http.MethodPost, adminAPI+"/users", k.adminToken(t), account); status != http.StatusCreated {
		t.Fatalf("creating the account %s answered %d %s", address, status, body)
	}
	var found []struct{ ID string }
	k.admin(t, "/users?exact=true&username="+url.QueryEscape(address), &found)
	if len(found) != 1 {
		t.Fatalf("the realm has %d accounts %s", len(found), address)
	}
	return found[0].ID
}

// signIn signs address in at Keycloak with password, as a person's browser does after Identity's
// sign-in route sent it there with the client identity, a state and a PKCE challenge, and returns the
// page that Keycloak shows next.
func (k *keycloak) signIn(t *testing.T, address, password string) string {
	t.Helper()
	browser := k.browser(t)
	verifier := rand.Text() + rand.Text()
	challenge := sha256.Sum256([]byte(verifier))
	start := "https://" + authenticationHostname + "/realms/" + realmName + "/protocol/openid-connect/auth?" + url.Values{
		"client_id": {identityClientID}, "redirect_uri": {callbackURL}, "response_type": {"code"}, "scope": {"openid"},
		"state": {rand.Text()}, "nonce": {rand.Text()},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}, "code_challenge_method": {"S256"},
	}.Encode()
	page := browse(t, browser, http.MethodGet, start, nil)
	form := regexp.MustCompile(`<form[^>]*id="kc-form-login"[^>]*>`).FindString(page)
	action := regexp.MustCompile(`action="([^"]*)"`).FindStringSubmatch(form)
	if action == nil {
		t.Fatalf("Keycloak's sign-in page has no form kc-form-login:\n%s", page)
	}
	return browse(t, browser, http.MethodPost, html.UnescapeString(action[1]),
		url.Values{"username": {address}, "password": {password}, "credentialId": {""}})
}

// browse sends one request of browser, with form when it is not nil, and returns the page of a 200.
func browse(t *testing.T, browser *http.Client, method, address string, form url.Values) string {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = bytes.NewBufferString(form.Encode())
	}
	request, err := http.NewRequest(method, address, body)
	if err != nil {
		t.Fatal(err)
	}
	if form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	answer, err := browser.Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v", method, address, err)
	}
	defer answer.Body.Close()
	page, err := io.ReadAll(answer.Body)
	if err != nil {
		t.Fatal(err)
	}
	if answer.StatusCode != http.StatusOK {
		t.Fatalf("%s %s answered %d %s", method, address, answer.StatusCode, page)
	}
	return string(page)
}

// browser is a person's browser on the authentication hostname. It reaches Keycloak through the mapped
// port, keeps Keycloak's cookies, and stops at a redirect that leaves the authentication hostname, such
// as the one to Identity's callback.
func (k *keycloak) browser(t *testing.T) *http.Client {
	t.Helper()
	endpoint, err := url.Parse(k.endpoint(t))
	if err != nil {
		t.Fatal(err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	var dialer net.Dialer
	return &http.Client{
		Jar:     jar,
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, endpoint.Host)
			},
			TLSClientConfig: trust(keycloakName),
		},
		CheckRedirect: func(request *http.Request, _ []*http.Request) error {
			if request.URL.Host != authenticationHostname {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// leftovers is what stopKeycloak removes at the end of the run. It is kept apart from keycloak because
// a start that fails half way leaves a container or a directory but no keycloak.
var leftovers struct {
	container testcontainers.Container
	dir       string
}

func stopKeycloak() {
	if leftovers.container != nil {
		_ = testcontainers.TerminateContainer(leftovers.container)
	}
	if leftovers.dir != "" {
		_ = os.RemoveAll(leftovers.dir)
	}
}
