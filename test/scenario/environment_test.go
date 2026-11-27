//go:build scenario

// Package scenario holds Identity's scenarios at the deployable contract seam (Identity ADR 0009,
// design section 13). Each scenario starts the image that the image target built, with inputs of its
// own, and drives it as Edge and the other deployables would. One run shares one Docker network, one
// throwaway certificate authority, one PostgreSQL, in which each scenario gets a database of its own,
// and one Keycloak at the test baseline, started when a scenario first needs it. testcontainers-go
// removes the containers, also when a run crashes, and the keys live only in memory and in temporary
// directories outside the repository.
package scenario

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/moby/moby/api/types/container"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/ancyloce/contelys-cloud-identity/test/fixture"
)

const (
	// image is the image that the image target built.
	image = "contelys/identity"
	// postgresImage is the PostgreSQL of the tests, the shared service library's pin.
	postgresImage = "postgres:18-alpine@sha256:0115267ab5a509022df9319c77be365cef335adb71556c75f60f5360ee247e71"
	// keycloakImage is the test baseline of design section 09, pinned by its index digest.
	keycloakImage = "quay.io/keycloak/keycloak:26.8.2@sha256:7e66a96e4739239070aeaf72e4c5decf0f7f682cfc725b9f7ea2b336eaba38b3"

	// listener is the port that Identity serves HTTPS on in the scenarios.
	listener = "8443/tcp"
	// inputsDir is where an Identity container mounts its inputs.
	inputsDir = "/etc/identity"
	// identityName is the name that Identity's certificate carries (ADR 0039).
	identityName = "identity"
	// revision is the configuration revision that the scenarios' files carry.
	revision = "0123456789abcdef0123456789abcdef01234567"
	// authenticationHostname is Keycloak's public hostname in the scenarios (design section 09).
	authenticationHostname = "auth.example.test"
)

// The environment that one run shares.
var (
	dockerNetwork *testcontainers.DockerNetwork
	ca            *fixture.Authority
	// sharedPostgres is the run's PostgreSQL, at the alias postgres on the run's network.
	sharedPostgres *postgresServer
	// password is the password of the role identity in every PostgreSQL of the run.
	password = rand.Text()
	// databases counts the databases that scenarios created, to name the next one.
	databases atomic.Int64
)

func TestMain(m *testing.M) {
	code, err := runWith(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, "the scenarios' environment:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func runWith(m *testing.M) (int, error) {
	ctx := context.Background()
	var err error
	if ca, err = fixture.NewAuthority(); err != nil {
		return 0, err
	}
	if dockerNetwork, err = network.New(ctx); err != nil {
		return 0, err
	}
	defer func() { _ = dockerNetwork.Remove(ctx) }()
	if sharedPostgres, err = startPostgres(ctx, "postgres"); err != nil {
		return 0, err
	}
	defer func() { _ = testcontainers.TerminateContainer(sharedPostgres.container) }()
	code := m.Run()
	stopKeycloak()
	return code, nil
}

// postgresServer is one PostgreSQL on the run's network, with the role identity that Identity connects as.
type postgresServer struct {
	container *postgres.PostgresContainer
	alias     string
}

// startPostgres starts a PostgreSQL at alias on the run's network and creates the role identity in it.
func startPostgres(ctx context.Context, alias string) (*postgresServer, error) {
	c, err := postgres.Run(ctx, postgresImage,
		postgres.WithUsername("admin"), postgres.WithPassword(rand.Text()),
		postgres.BasicWaitStrategies(), network.WithNetwork([]string{alias}, dockerNetwork))
	if err != nil {
		return nil, err
	}
	d := &postgresServer{container: c, alias: alias}
	// rand.Text is base32, so the password needs no escaping.
	if err := d.exec(ctx, "CREATE ROLE identity LOGIN PASSWORD '"+password+"'"); err != nil {
		_ = testcontainers.TerminateContainer(c)
		return nil, err
	}
	return d, nil
}

func (d *postgresServer) exec(ctx context.Context, sql string) error {
	address, err := d.container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		return err
	}
	conn, err := pgx.Connect(ctx, address)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	_, err = conn.Exec(ctx, sql)
	return err
}

// create creates an empty database that the role identity owns, and returns the address at which
// Identity reaches it, without a password.
func (d *postgresServer) create(t *testing.T) string {
	t.Helper()
	name := fmt.Sprintf("identity_%d", databases.Add(1))
	if err := d.exec(context.Background(), "CREATE DATABASE "+name+" OWNER identity"); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("postgres://identity@%s:5432/%s?sslmode=disable", d.alias, name)
}

// inputs is what one Identity instance reads, in a directory that it mounts at /etc/identity: its
// configuration, its certificate and the trust store, and its secrets as files (ADR 0020).
type inputs struct {
	dir string
}

// The paths of the inputs, relative to the directory.
const (
	configFile          = "config.yaml"
	internalSigningKey  = "secrets/internal-signing-key.pem"
	workloadSigningKey  = "secrets/workload-signing-key.pem"
	databasePassword    = "secrets/database-password"
	identityCertificate = "tls/identity.crt"
	identityKey         = "tls/identity.key"
	trustStore          = "tls/ca.crt"
)

// newInputs writes a complete set of inputs for an instance whose database is at databaseURL.
func newInputs(t *testing.T, databaseURL string) *inputs {
	t.Helper()
	in := &inputs{dir: t.TempDir()}
	certificate, key, _ := ca.Issue(t, identityName)
	in.write(t, identityCertificate, certificate)
	in.write(t, identityKey, key)
	in.write(t, trustStore, ca.PEM)
	in.write(t, databasePassword, []byte(password+"\n"))
	in.write(t, internalSigningKey, fixture.SigningKey(t))
	in.write(t, workloadSigningKey, fixture.SigningKey(t))
	in.write(t, configFile, []byte(fmt.Sprintf(`revision: %s
listen: ":8443"
tls:
  certificate: %[2]s/%[3]s
  key: %[2]s/%[4]s
  authority: %[2]s/%[5]s
database:
  url: %[6]s
  password_file: %[2]s/%[7]s
signing_keys:
  internal: %[2]s/%[8]s
  workload: %[2]s/%[9]s
`, revision, inputsDir, identityCertificate, identityKey, trustStore, databaseURL, databasePassword,
		internalSigningKey, workloadSigningKey)))
	return in
}

// write writes one input file, readable for the user that Identity runs as, as a deployment gives it.
func (in *inputs) write(t *testing.T, name string, content []byte) {
	t.Helper()
	path := filepath.Join(in.dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(in.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// The file is written beside its place and renamed into it, so that Identity never reads half of it.
	next := path + ".next"
	if err := os.WriteFile(next, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(next, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, path); err != nil {
		t.Fatal(err)
	}
}

// remove removes one input file.
func (in *inputs) remove(t *testing.T, name string) {
	t.Helper()
	if err := os.Remove(filepath.Join(in.dir, name)); err != nil {
		t.Fatal(err)
	}
}

// identity is one running Identity instance.
type identity struct {
	container *testcontainers.DockerContainer
}

// startIdentity starts an Identity instance that mounts in, and waits until it is live, which says
// nothing yet about whether it is ready.
func startIdentity(t *testing.T, in *inputs) *identity {
	t.Helper()
	c, err := testcontainers.GenericContainer(context.Background(), testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:          image,
			ExposedPorts:   []string{listener},
			Networks:       []string{dockerNetwork.Name},
			NetworkAliases: map[string][]string{dockerNetwork.Name: {identityName}},
			HostConfigModifier: func(hc *container.HostConfig) {
				hc.Binds = append(hc.Binds, in.dir+":"+inputsDir+":ro")
			},
			WaitingFor: wait.ForHTTP("/livez").WithPort(listener).
				WithTLS(true, trust(identityName)).
				WithStartupTimeout(time.Minute),
		},
		Started: true,
	})
	testcontainers.CleanupContainer(t, c)
	if c != nil {
		t.Cleanup(func() { printLogs(t, c) })
	}
	if err != nil {
		t.Fatalf("start Identity: %v", err)
	}
	return &identity{container: c.(*testcontainers.DockerContainer)}
}

// printLogs shows the container's logs when the scenario failed.
func printLogs(t *testing.T, c testcontainers.Container) {
	if !t.Failed() {
		return
	}
	t.Logf("the container's logs:\n%s", output(c))
}

// output is what the container c wrote, or why it cannot be read.
func output(c testcontainers.Container) string {
	logs, err := c.Logs(context.Background())
	if err != nil {
		return err.Error()
	}
	defer logs.Close()
	content, err := io.ReadAll(logs)
	if err != nil {
		return err.Error()
	}
	return string(content)
}

// lastLines returns the last n lines that the container c wrote, or why they cannot be read.
func lastLines(c testcontainers.Container, n int) string {
	if c == nil {
		return "(no container)"
	}
	lines := strings.Split(strings.TrimSpace(output(c)), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// trust verifies a server's certificate for name against the run's certificate authority alone.
func trust(name string) *tls.Config {
	return &tls.Config{RootCAs: ca.Pool(), ServerName: name}
}

// client sends requests to Identity over TLS and verifies its certificate against the run's
// certificate authority. It presents certificate when it is not nil.
func (i *identity) client(certificate *tls.Certificate) *http.Client {
	config := trust(identityName)
	if certificate != nil {
		config.Certificates = []tls.Certificate{*certificate}
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: config},
		Timeout:   10 * time.Second,
		// A redirect is an answer of Identity's to look at, not to follow.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// url is the address of path on the instance, as this test process reaches it.
func (i *identity) url(t *testing.T, path string) string {
	t.Helper()
	endpoint, err := i.container.PortEndpoint(context.Background(), listener, "https")
	if err != nil {
		t.Fatal(err)
	}
	return endpoint + path
}

// do sends one request without a body, presenting certificate when it is not nil, and returns the
// answer with its body read.
func (i *identity) do(t *testing.T, method, path string, header http.Header, certificate *tls.Certificate) (*http.Response, []byte) {
	t.Helper()
	request, err := http.NewRequest(method, i.url(t, path), nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, values := range header {
		request.Header[name] = values
	}
	answer, err := i.client(certificate).Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer answer.Body.Close()
	body, err := io.ReadAll(answer.Body)
	if err != nil {
		t.Fatal(err)
	}
	return answer, body
}

// readiness is the body of GET /readyz.
type readiness struct {
	Ready  bool `json:"ready"`
	Checks []struct {
		Name     string `json:"name"`
		Required bool   `json:"required"`
		OK       bool   `json:"ok"`
	} `json:"checks"`
}

// failing names the required checks that failed.
func (r readiness) failing() []string {
	var names []string
	for _, check := range r.Checks {
		if check.Required && !check.OK {
			names = append(names, check.Name)
		}
	}
	return names
}

// readiness asks the instance whether it is ready, without a client certificate, as Edge's health
// checks and the platform's probes do (design section 12).
func (i *identity) readiness(t *testing.T) (int, readiness) {
	t.Helper()
	answer, body := i.do(t, http.MethodGet, "/readyz", nil, nil)
	var r readiness
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatalf("GET /readyz answered %d with %q: %v", answer.StatusCode, body, err)
	}
	return answer.StatusCode, r
}

// becomesReady waits until the instance reports ready, and fails the scenario with what it last
// answered.
func (i *identity) becomesReady(t *testing.T, when string) {
	t.Helper()
	eventually(t, 30*time.Second, func() (bool, string) {
		status, r := i.readiness(t)
		return status == http.StatusOK && r.Ready, when + ": " + describe(status, r)
	})
}

// becomesNotReady waits until the instance reports not ready, with exactly failing as the required
// checks that fail.
func (i *identity) becomesNotReady(t *testing.T, when string, failing ...string) {
	t.Helper()
	eventually(t, 30*time.Second, func() (bool, string) {
		status, r := i.readiness(t)
		return status == http.StatusServiceUnavailable && !r.Ready && slices.Equal(r.failing(), failing),
			when + ": " + describe(status, r)
	})
}

// describe says what GET /readyz answered, for a failed scenario.
func describe(status int, r readiness) string {
	return fmt.Sprintf("GET /readyz answered %d, ready %t, failing %v", status, r.Ready, r.failing())
}

// eventually asks condition every half second until it holds or timeout passes, and then fails the
// scenario with what condition last reported.
func eventually(t *testing.T, timeout time.Duration, condition func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		ok, state := condition()
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("after %s: %s", timeout, state)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// contains reports whether s holds every one of parts.
func contains(s string, parts ...string) bool {
	for _, part := range parts {
		if !strings.Contains(s, part) {
			return false
		}
	}
	return true
}
