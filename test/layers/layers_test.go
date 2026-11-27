//go:build layers

// Package layers is the check of the layers' imports that lint runs (Identity ADR 0009). It reads go
// list -json ./... and refuses every import that the table under "Layers" of the layout standard does
// not allow: an import points inward only, toward domain/; domain/ and application/ import nothing
// from outside the module but the standard library; and interfaces/ and infrastructure/ import from
// outside the module only the modules that the table gives each, which outside lists. The composition
// root under cmd/ and the tests under test/ may import every layer. Only the imports of the code are
// checked; the tests beside it sit at no seam inside Identity (Q10 of the plan) and may use test tools.
package layers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// layers are the four layers, by their directory under internal/.
var layers = []string{"interfaces", "application", "domain", "infrastructure"}

// inward lists, for each layer, the layers of the module that it may import.
var inward = map[string][]string{
	"domain":         {"domain"},
	"application":    {"application", "domain"},
	"interfaces":     {"interfaces", "application", "domain"},
	"infrastructure": {"infrastructure", "application", "domain"},
}

// sharedLibrary is the shared service library, which both outer layers may import.
const sharedLibrary = "github.com/ancyloce/contelys-cloud-libs-service"

// outside lists, for each outer layer, the modules from outside Identity's module that it may import:
// the libraries of Identity ADR 0009, each in the layer that the table under "Layers" gives its kind.
// A library that Identity adds is placed here, in its layer, with the record that adds it.
var outside = map[string][]string{
	// The framework is the standard library's router. Generated server code imports oapi-codegen's
	// runtime, and the problem body takes its correlation ID from OpenTelemetry's trace, on which the
	// shared library's telemetry is built.
	"interfaces": {
		sharedLibrary,
		"github.com/oapi-codegen/runtime",
		"go.opentelemetry.io/otel/trace",
	},
	// The drivers, the clients of infrastructure products and generated client code.
	"infrastructure": {
		sharedLibrary,
		"github.com/jackc/pgx/v5",
		"github.com/pressly/goose/v3",
		"github.com/riverqueue/river",
		"github.com/twmb/franz-go",
		"google.golang.org/protobuf",
		"github.com/coreos/go-oidc/v3",
		"golang.org/x/oauth2",
		"github.com/go-jose/go-jose/v4",
		"github.com/oapi-codegen/runtime",
	},
}

func TestEveryImportPointsInward(t *testing.T) {
	module := goList(t, "list", "-m")[0]
	standard := map[string]bool{}
	for _, path := range goList(t, "list", "std") {
		standard[path] = true
	}
	var packages []struct {
		ImportPath string
		Imports    []string
	}
	decoder := json.NewDecoder(bytes.NewReader(goOutput(t, "list", "-json", "./...")))
	for decoder.More() {
		var p struct {
			ImportPath string
			Imports    []string
		}
		if err := decoder.Decode(&p); err != nil {
			t.Fatal(err)
		}
		packages = append(packages, p)
	}

	checked := map[string]int{}
	for _, p := range packages {
		layer, inInternal := layerOf(module, p.ImportPath)
		if !inInternal {
			continue
		}
		if layer == "" {
			t.Errorf("%s lies under internal/ in none of the layers %v", p.ImportPath, layers)
			continue
		}
		checked[layer]++
		for _, imported := range p.Imports {
			if err := refusal(module, layer, imported, standard); err != nil {
				t.Errorf("%s imports %s: %v", p.ImportPath, imported, err)
			}
		}
	}
	// A check that finds no package of a layer would pass by checking nothing.
	if checked["interfaces"] == 0 || checked["infrastructure"] == 0 {
		t.Errorf("the check found the packages %v of each layer, which leaves out a layer that Identity has", checked)
	}
}

// The check refuses each import that the layout standard forbids, and lets through what it allows.
func TestTheCheckRefusesWhatTheStandardForbids(t *testing.T) {
	const module = "example.test/service"
	standard := map[string]bool{"context": true, "net/http": true, "time": true}
	for _, c := range []struct {
		layer, imported string
		allowed         bool
	}{
		{"domain", module + "/internal/domain/sessions", true},
		{"domain", "time", true},
		{"domain", module + "/internal/application/admission", false},
		{"domain", module + "/internal/infrastructure/postgres", false},
		{"domain", module + "/internal/interfaces/httpapi", false},
		{"domain", "github.com/jackc/pgx/v5", false},
		{"domain", "github.com/ancyloce/contelys-cloud-libs-service/outbox", false},

		{"application", module + "/internal/domain/principals", true},
		{"application", module + "/internal/application/tokens", true},
		{"application", "context", true},
		{"application", module + "/internal/infrastructure/postgres", false},
		{"application", module + "/internal/interfaces/httpapi/gen", false},
		{"application", "github.com/ancyloce/contelys-cloud-libs-service/outbox", false},
		{"application", "github.com/jackc/pgx/v5", false},

		{"interfaces", module + "/internal/application/admission", true},
		{"interfaces", module + "/internal/interfaces/httpapi/gen", true},
		{"interfaces", "github.com/ancyloce/contelys-cloud-libs-service/health", true},
		{"interfaces", "net/http", true},
		{"interfaces", "github.com/oapi-codegen/runtime/types", true},
		{"interfaces", module + "/internal/infrastructure/postgres", false},
		{"interfaces", "github.com/jackc/pgx/v5", false},
		{"interfaces", "github.com/pressly/goose/v3", false},
		{"interfaces", "github.com/example/unlisted", false},

		{"infrastructure", module + "/internal/application/admission", true},
		{"infrastructure", module + "/internal/domain/principals", true},
		{"infrastructure", "github.com/jackc/pgx/v5/pgxpool", true},
		{"infrastructure", "github.com/ancyloce/contelys-cloud-libs-service/outbox", true},
		{"infrastructure", module + "/internal/interfaces/httpapi", false},
		{"infrastructure", "github.com/example/unlisted", false},
		{"infrastructure", "github.com/jackc/pgxfake", false},

		{"interfaces", module + "/cmd/identity", false},
		{"infrastructure", module + "/test/fixture", false},
		{"application", module + "/internal/helpers", false},
	} {
		err := refusal(module, c.layer, c.imported, standard)
		if (err == nil) != c.allowed {
			t.Errorf("%s importing %s: allowed %t, want %t (%v)", c.layer, c.imported, err == nil, c.allowed, err)
		}
	}
}

// layerOf names the layer of the package at path of module, and reports whether the package lies
// under internal/. The layer is empty for a package under internal/ that no layer holds.
func layerOf(module, path string) (layer string, inInternal bool) {
	rest, found := strings.CutPrefix(path, module+"/internal/")
	if !found {
		return "", false
	}
	first, _, _ := strings.Cut(rest, "/")
	if slices.Contains(layers, first) {
		return first, true
	}
	return "", true
}

// refusal is why the layer may not import the package imported, or nil when it may.
func refusal(module, layer, imported string, standard map[string]bool) error {
	if standard[imported] {
		return nil
	}
	if within(imported, module) {
		target, inInternal := layerOf(module, imported)
		switch {
		case !inInternal:
			return errors.New("only the composition root and the tests import code outside internal/")
		case target == "":
			return errors.New("the package lies in no layer")
		case !slices.Contains(inward[layer], target):
			return fmt.Errorf("%s may import only %v of the module", layer, inward[layer])
		}
		return nil
	}
	if !slices.ContainsFunc(outside[layer], func(m string) bool { return within(imported, m) }) {
		return fmt.Errorf("%s may import from outside the module only the standard library and %v", layer, outside[layer])
	}
	return nil
}

// within reports whether the package path lies in the module m.
func within(path, m string) bool {
	return path == m || strings.HasPrefix(path, m+"/")
}

// goList runs go with args in the module's directory and returns the lines that it wrote.
func goList(t *testing.T, args ...string) []string {
	t.Helper()
	return strings.Fields(string(goOutput(t, args...)))
}

func goOutput(t *testing.T, args ...string) []byte {
	t.Helper()
	command := exec.Command("go", args...)
	command.Dir = "../.."
	var stderr bytes.Buffer
	command.Stderr = &stderr
	out, err := command.Output()
	if err != nil {
		t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return out
}
