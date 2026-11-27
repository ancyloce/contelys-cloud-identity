// Command identity is Identity's composition root (Identity ADR 0009). Without a subcommand it serves
// Identity's routes and internal operations over HTTPS, with its configuration from the file that
// Ansible renders, its telemetry and its health endpoints from the shared service library.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata" // The image FROM scratch holds no time-zone data of its own.

	"github.com/ancyloce/contelys-cloud-libs-service/config"
	"github.com/ancyloce/contelys-cloud-libs-service/health"
	"github.com/ancyloce/contelys-cloud-libs-service/telemetry"

	"github.com/ancyloce/contelys-cloud-identity/internal/application/admission"
	"github.com/ancyloce/contelys-cloud-identity/internal/application/signin"
	"github.com/ancyloce/contelys-cloud-identity/internal/application/tokens"
	"github.com/ancyloce/contelys-cloud-identity/internal/infrastructure/keycloak"
	"github.com/ancyloce/contelys-cloud-identity/internal/infrastructure/postgres"
	"github.com/ancyloce/contelys-cloud-identity/internal/infrastructure/signing"
	"github.com/ancyloce/contelys-cloud-identity/internal/interfaces/commands"
	"github.com/ancyloce/contelys-cloud-identity/internal/interfaces/httpapi"
)

// slug is Identity's slug, which names it in its telemetry and which its certificate carries.
const slug = "identity"

// settings is Identity's configuration. Every path names a file that the deployment mounts; the
// secrets among them reach Identity only as files (ADR 0020).
type settings struct {
	// Listen is the address that Identity serves HTTPS on, such as ":8443".
	Listen string `yaml:"listen"`
	TLS    struct {
		// Certificate and Key are Identity's certificate, for the name identity, and its key.
		Certificate string `yaml:"certificate"`
		Key         string `yaml:"key"`
		// Authority is the installation's certificate authority, which verifies the client
		// certificates that callers present (ADR 0039).
		Authority string `yaml:"authority"`
	} `yaml:"tls"`
	Database struct {
		// URL is Identity's database, without a password.
		URL string `yaml:"url"`
		// PasswordFile holds the database password.
		PasswordFile string `yaml:"password_file"`
	} `yaml:"database"`
	SigningKeys struct {
		// Internal and Workload hold the keys that sign internal and workload tokens, each an
		// Ed25519 key in PKCS #8 PEM (ADR 0052).
		Internal string `yaml:"internal"`
		Workload string `yaml:"workload"`
	} `yaml:"signing_keys"`
	// ApplicationOrigin is the origin of the authoring app, such as https://app.example.test, whose
	// paths a sign-in returns to and whose callback Keycloak redirects to.
	ApplicationOrigin string `yaml:"application_origin"`
	Keycloak          struct {
		// PublicURL is the authentication hostname, such as https://auth.example.test, which names
		// the realm's issuer and its authorization endpoint (ADR 0064).
		PublicURL string `yaml:"public_url"`
		// InternalURL is Keycloak's internal address, such as https://keycloak:8443, of its token
		// and keys endpoints, which Identity configures statically, without discovery.
		InternalURL string `yaml:"internal_url"`
		Realm       string `yaml:"realm"`
		// ClientID is the client through which Identity signs browsers in, and ClientSecretFile
		// holds its secret.
		ClientID         string `yaml:"client_id"`
		ClientSecretFile string `yaml:"client_secret_file"`
	} `yaml:"keycloak"`
}

func validate(s settings) error {
	for _, setting := range []struct{ name, value string }{
		{"listen", s.Listen},
		{"tls.certificate", s.TLS.Certificate},
		{"tls.key", s.TLS.Key},
		{"tls.authority", s.TLS.Authority},
		{"database.url", s.Database.URL},
		{"database.password_file", s.Database.PasswordFile},
		{"signing_keys.internal", s.SigningKeys.Internal},
		{"signing_keys.workload", s.SigningKeys.Workload},
		{"application_origin", s.ApplicationOrigin},
		{"keycloak.public_url", s.Keycloak.PublicURL},
		{"keycloak.internal_url", s.Keycloak.InternalURL},
		{"keycloak.realm", s.Keycloak.Realm},
		{"keycloak.client_id", s.Keycloak.ClientID},
		{"keycloak.client_secret_file", s.Keycloak.ClientSecretFile},
	} {
		if setting.value == "" {
			return fmt.Errorf("%s is required", setting.name)
		}
	}
	return nil
}

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout))
}

// run runs the command line args and returns the process's exit code. It writes to out. Without a
// subcommand Identity serves; health checks the readiness of the instance on this host; disable,
// enable and erase are the operator commands.
func run(ctx context.Context, args []string, out io.Writer) int {
	if len(args) > 0 {
		switch {
		case args[0] == "health":
			return checkHealth(ctx, args[1:], out)
		case slices.Contains(commands.Kinds, args[0]):
			return operate(args[0], args[1:], out)
		}
	}
	return serve(ctx, args, out)
}

// configFlag parses args for the flag -config of the command name, which every command takes, and
// refuses any other argument, such as a misspelt subcommand.
func configFlag(name string, args []string, out io.Writer) (string, bool) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(out)
	path := flags.String("config", "", "the configuration file that Ansible renders")
	if err := flags.Parse(args); err != nil {
		return "", false
	}
	if flags.NArg() > 0 {
		fmt.Fprintln(out, name+": unexpected arguments:", strings.Join(flags.Args(), " "))
		return "", false
	}
	return *path, true
}

// operate runs the operator command kind. Recording the operation is not built yet, so a complete
// command line is refused after it has been checked.
func operate(kind string, args []string, out io.Writer) int {
	if _, _, err := commands.ParseOperation(kind, args, out); err != nil {
		return 2
	}
	fmt.Fprintf(out, "identity %s: this version of Identity cannot record an operation yet\n", kind)
	return 1
}

// openConfig opens the configuration file at path.
func openConfig(path string) (*config.Store[settings], error) {
	if path == "" {
		return nil, errors.New("no configuration file: pass -config")
	}
	return config.Open(path, config.Options[settings]{Validate: validate})
}

// checkHealth asks the instance that the configuration describes, on this host, whether it is ready,
// and exits 0 when it is, so that Docker and Compose check readiness without a shell.
func checkHealth(ctx context.Context, args []string, out io.Writer) int {
	path, ok := configFlag(slug+" health", args, out)
	if !ok {
		return 2
	}
	store, err := openConfig(path)
	if err != nil {
		fmt.Fprintln(out, "identity health:", err)
		return 2
	}
	values := store.Current().Values
	address, err := localAddress(values.Listen)
	if err != nil {
		fmt.Fprintln(out, "identity health: listen:", err)
		return 2
	}
	authority, err := readPool(values.TLS.Authority)
	if err != nil {
		fmt.Fprintln(out, "identity health:", err)
		return 2
	}
	if err := commands.Health(ctx, address, authority, slug); err != nil {
		fmt.Fprintln(out, "identity health:", err)
		return 1
	}
	return 0
}

// localAddress is where a command on this host reaches the listen address: its own host, or the
// loopback address when it listens on every address.
func localAddress(listen string) (string, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", err
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port), nil
}

// serve serves until ctx ends or the process receives SIGTERM or SIGINT.
func serve(ctx context.Context, args []string, out io.Writer) int {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, os.Interrupt)
	defer stop()
	path, ok := configFlag(slug, args, out)
	if !ok {
		return 2
	}

	// No exporter yet: the spans are dropped until Identity sends them to the OpenTelemetry
	// Collector (issue 11 of the phase 1 platform). The trace context still travels, and the logs
	// still carry it.
	logger, shutdown := telemetry.Setup(slug, nil, out)
	defer func() { _ = shutdown(context.WithoutCancel(ctx)) }()
	store, err := openConfig(path)
	if err != nil {
		logger.Error("the configuration was refused", "error", err)
		return 1
	}
	go store.Watch(ctx, time.Second, func(err error) {
		if errors.Is(err, config.ErrRestartRequired) {
			logger.Warn("a changed configuration waits for the next restart", "error", err)
			return
		}
		logger.Error("a changed configuration was refused", "error", err)
	})
	values := store.Current().Values

	authority, err := readPool(values.TLS.Authority)
	if err != nil {
		logger.Error("the certificate authority was refused", "error", err)
		return 1
	}
	tlsConfig, err := serverTLS(values, authority)
	if err != nil {
		logger.Error("the TLS files were refused", "error", err)
		return 1
	}
	database, err := postgres.Open(values.Database.URL, values.Database.PasswordFile)
	if err != nil {
		logger.Error("the database settings were refused", "error", err)
		return 1
	}
	defer database.Close()
	go migrate(ctx, database, logger)
	keys := signing.NewKeys(values.SigningKeys.Internal, values.SigningKeys.Workload)
	authorizationServer := keycloak.New(keycloak.Settings{
		PublicURL:        values.Keycloak.PublicURL,
		InternalURL:      values.Keycloak.InternalURL,
		Realm:            values.Keycloak.Realm,
		ClientID:         values.Keycloak.ClientID,
		ClientSecretFile: values.Keycloak.ClientSecretFile,
		RedirectURL:      strings.TrimSuffix(values.ApplicationOrigin, "/") + callbackPath,
		// Identity trusts only the installation's certificate authority (ADR 0039).
		Client: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: authority}}, Timeout: keycloakTimeout},
	})

	router := httpapi.New(func() (string, string) {
		snapshot := store.Current()
		return snapshot.Revision, snapshot.Digest
	}, httpapi.UseCases{
		SignIn: signin.Service{
			Attempts: database.Attempts(), Keycloak: authorizationServer, Principals: database.Principals(),
			Sessions: database.Sessions(), Now: time.Now,
		},
		Admission: admission.Service{Sessions: database.Sessions(), Tokens: keys, Now: time.Now},
		KeySet:    tokens.KeySet{Signer: keys},
		Logger:    logger,
	},
		// Readiness says that Identity can decide admission (design section 12).
		health.Check{Name: "database", Required: true, Run: database.Check},
		health.Check{Name: "signing-keys", Required: true, Run: keys.Check},
	)
	server := &http.Server{
		Addr:              values.Listen,
		Handler:           router,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	served := make(chan error, 1)
	go func() { served <- server.ListenAndServeTLS("", "") }()
	logger.Info("serving", "revision", store.Current().Revision)

	select {
	case err := <-served:
		logger.Error("the server stopped", "error", err)
		return 1
	case <-ctx.Done():
	}
	stopping, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(stopping); err != nil {
		logger.Error("the server did not stop in time", "error", err)
		return 1
	}
	return 0
}

// callbackPath is the path of the contract's operation completeSignIn, the one redirect address of the
// client identity in the realm.
const callbackPath = "/api/identity/v1/session/callback"

// keycloakTimeout bounds each call to Keycloak.
const keycloakTimeout = 5 * time.Second

// migrationRetry is how long an instance waits before it tries its migrations again.
const migrationRetry = 2 * time.Second

// migrate applies the migrations at the start of every instance, before its database check can pass,
// and tries again until they are applied, so that an instance started before its database becomes
// ready once the database answers.
func migrate(ctx context.Context, database *postgres.Database, logger *slog.Logger) {
	for {
		err := database.Migrate(ctx)
		if err == nil {
			logger.Info("the migrations are applied")
			return
		}
		logger.Warn("the migrations could not be applied, and are tried again", "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(migrationRetry):
		}
	}
}

// serverTLS serves Identity's certificate and asks every caller for a client certificate, which it
// verifies against the installation's certificate authority when one is presented. Only the
// authentication endpoint requires one (design section 12).
func serverTLS(s settings, authority *x509.CertPool) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(s.TLS.Certificate, s.TLS.Key)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    authority,
	}, nil
}

// readPool reads a certificate authority's PEM file into a pool that trusts it alone.
func readPool(path string) (*x509.CertPool, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(content) {
		return nil, fmt.Errorf("%s holds no certificate", path)
	}
	return pool, nil
}
