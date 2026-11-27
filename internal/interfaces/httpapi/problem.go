package httpapi

import (
	"encoding/json"
	"net/http"

	"go.opentelemetry.io/otel/trace"

	"github.com/ancyloce/contelys-cloud-identity/internal/interfaces/httpapi/gen"
)

// The one title of each code that Identity answers so far. A code keeps its title (ADR 0054).
const (
	unavailableTitle       = "The service cannot complete the request now."
	notPermittedTitle      = "The caller may not call this operation."
	invalidRequestTitle    = "The request does not match the contract."
	sessionRequiredTitle   = "The request needs a live session."
	invalidReturnPathTitle = "The return path is not a path of the application."
	signInFailedTitle      = "The sign-in failed."
	notActiveTitle         = "The principal may not use the application."
)

// idLimit is the most characters that the problem body gives requestId and correlationId.
const idLimit = 128

// writeProblem answers r with status and the problem body of Identity's contract with code and
// title (ADR 0054). requestId is the request ID that Edge set in X-Request-Id, and correlationId the
// request's trace ID, or the request ID when the request carries no trace. The body names no
// address, no name, no credential and no token.
func writeProblem(w http.ResponseWriter, r *http.Request, status int, code gen.IdentityErrorCode, title string) {
	body := gen.IdentityProblem{
		Type:      "about:blank",
		Title:     title,
		Status:    status,
		Code:      code,
		RequestId: limited(r.Header.Get("X-Request-Id")),
	}
	body.CorrelationId = body.RequestId
	if span := trace.SpanContextFromContext(r.Context()); span.HasTraceID() {
		body.CorrelationId = span.TraceID().String()
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// limited cuts s to idLimit bytes.
func limited(s string) string {
	if len(s) > idLimit {
		return s[:idLimit]
	}
	return s
}
