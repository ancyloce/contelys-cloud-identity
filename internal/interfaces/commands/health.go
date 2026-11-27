// Package commands holds Identity's subcommands beside the server (Identity ADR 0009): health, which
// checks an instance's readiness for Docker and Compose, and the operator commands of design section
// 07.
package commands

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"time"
)

// healthTimeout bounds the whole check, below the timeout of the image's health check.
const healthTimeout = 2 * time.Second

// Health asks the instance at address whether it is ready, over TLS, verifying its certificate for
// serverName against roots, and returns nil when GET /readyz answers 200. It presents no client
// certificate, as no prober does (design section 12).
func Health(ctx context.Context, address string, roots *x509.CertPool, serverName string) error {
	ctx, cancel := context.WithTimeout(ctx, healthTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+address+"/readyz", nil)
	if err != nil {
		return err
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: serverName}}}
	answer, err := client.Do(request)
	if err != nil {
		return err
	}
	defer answer.Body.Close()
	if answer.StatusCode != http.StatusOK {
		return fmt.Errorf("not ready: GET /readyz answered %d", answer.StatusCode)
	}
	return nil
}
