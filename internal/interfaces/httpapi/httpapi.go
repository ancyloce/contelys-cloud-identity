// Package httpapi is Identity's interface layer over HTTP (the layout standard, "Structure of a
// domain service"): the health endpoints of the shared service library, and the operations of
// Identity's contract through the server stubs generated under gen/, each traced under its own route.
package httpapi

import (
	"net/http"

	"github.com/ancyloce/contelys-cloud-libs-service/health"
	"github.com/ancyloce/contelys-cloud-libs-service/telemetry"

	"github.com/ancyloce/contelys-cloud-identity/internal/interfaces/httpapi/gen"
)

// authenticationPattern is the route of the authentication endpoint, as the stubs register it.
const authenticationPattern = http.MethodGet + " /internal/v1/authentication"

// edgeName is the name that Edge's certificate carries (ADR 0039).
const edgeName = "edge"

// Router routes Identity's HTTP requests on the standard library's router.
type Router struct {
	mux *http.ServeMux
}

// New returns a router that serves GET /livez, GET /readyz and GET /revision outside any trace, to
// callers with or without a client certificate, and every operation of Identity's contract. applied
// reports the revision and digest of the configuration in force, and checks are Identity's signals
// of readiness.
func New(applied func() (revision, digest string), checks ...health.Check) *Router {
	probes := health.Handler(applied, checks...)
	mux := http.NewServeMux()
	for _, probe := range []string{"/livez", "/readyz", "/revision"} {
		mux.Handle("GET "+probe, probes)
	}
	router := &Router{mux: mux}
	gen.HandlerWithOptions(operations{}, gen.StdHTTPServerOptions{BaseRouter: router, ErrorHandlerFunc: invalidParameter})
	return router
}

// HandleFunc registers one operation of the contract, as the generated stubs call it, traced with W3C
// Trace Context under pattern as its http.route. The authentication endpoint admits Edge alone.
func (r *Router) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	var h http.Handler = http.HandlerFunc(handler)
	if pattern == authenticationPattern {
		h = requireEdge(h)
	}
	r.mux.Handle(pattern, telemetry.Handler(h, pattern))
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mux.ServeHTTP(w, req)
}

// requireEdge lets a call through only when the caller presented a certificate for the name edge,
// which the TLS handshake verified against the installation's certificate authority. Identity asks
// every caller for a certificate and requires one here alone (design sections 05 and 12). Any other
// caller is answered 403 operation_not_permitted.
func requireEdge(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || r.TLS.VerifiedChains[0][0].VerifyHostname(edgeName) != nil {
			writeProblem(w, r, http.StatusForbidden, gen.IdentityErrorCodeOperationNotPermitted, notPermittedTitle)
			return
		}
		next.ServeHTTP(w, r)
	})
}
