//go:build scenario

package scenario

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"testing"

	contracts "github.com/ancyloce/contelys-cloud-contracts"
	"go.yaml.in/yaml/v3"
)

// authenticationPath is the path of the authentication endpoint in Identity's contract.
const authenticationPath = "/internal/v1/authentication"

// Identity asks every caller for a client certificate and requires one named edge on the
// authentication endpoint alone, so that it hands out internal tokens to Edge alone, while every
// other operation of its contract and its health endpoints answer without one (design sections 05
// and 12, ADR 0039).
func TestOnlyTheAuthenticationEndpointRequiresEdgesCertificate(t *testing.T) {
	instance := startIdentity(t, newInputs(t, sharedPostgres.create(t)))
	_, _, edge := ca.Issue(t, "edge")
	_, _, notifications := ca.Issue(t, "notifications")

	for _, caller := range []struct {
		name        string
		certificate *tls.Certificate
	}{
		{"a caller without a certificate", nil},
		{"a caller with a certificate named notifications", &notifications},
	} {
		answer, body := instance.do(t, http.MethodGet, authenticationPath, forwarded(), caller.certificate)
		if !refused(answer, body) {
			t.Errorf("%s: GET %s answered %d %q, want 403 operation_not_permitted", caller.name, authenticationPath, answer.StatusCode, body)
		}
	}
	if answer, body := instance.do(t, http.MethodGet, authenticationPath, forwarded(), &edge); refused(answer, body) {
		t.Errorf("Edge: GET %s was refused: %d %q", authenticationPath, answer.StatusCode, body)
	}

	operations := contractOperations(t)
	if len(operations) < 2 {
		t.Fatalf("the contract lists %d operations", len(operations))
	}
	for _, operation := range operations {
		method, path, _ := strings.Cut(operation, " ")
		if path == authenticationPath {
			continue
		}
		if answer, body := instance.do(t, method, path, nil, nil); refused(answer, body) {
			t.Errorf("%s without a certificate was refused: %d %q", operation, answer.StatusCode, body)
		}
	}
	for _, probe := range []string{"/livez", "/readyz", "/revision"} {
		if answer, body := instance.do(t, http.MethodGet, probe, nil, nil); answer.StatusCode != http.StatusOK {
			t.Errorf("GET %s without a certificate answered %d %q", probe, answer.StatusCode, body)
		}
	}
}

// refused reports whether answer is the refusal of a caller that is not Edge: 403 with the problem
// body and the code operation_not_permitted.
func refused(answer *http.Response, body []byte) bool {
	var problem struct {
		Code string `json:"code"`
	}
	return answer.StatusCode == http.StatusForbidden &&
		answer.Header.Get("Content-Type") == "application/problem+json" &&
		json.Unmarshal(body, &problem) == nil && problem.Code == "operation_not_permitted"
}

// contractOperations lists each operation of Identity's contract, in the contracts module at the
// version that go.mod requires, as "METHOD /path".
func contractOperations(t *testing.T) []string {
	t.Helper()
	content, err := contracts.OpenAPI.ReadFile("openapi/identity/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var contract struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(content, &contract); err != nil {
		t.Fatal(err)
	}
	var operations []string
	for path, methods := range contract.Paths {
		for method := range methods {
			switch method {
			case "get", "put", "post", "delete", "patch":
				operations = append(operations, strings.ToUpper(method)+" "+path)
			}
		}
	}
	sort.Strings(operations)
	return operations
}
