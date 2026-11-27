package httpapi

import (
	"net/http"

	"github.com/ancyloce/contelys-cloud-identity/internal/interfaces/httpapi/gen"
)

// operations serves the operations of Identity's contract. An operation that its ticket has not
// built yet answers 503 unavailable, which every operation of the contract may answer, with
// Cache-Control no-store, which those of registration and sign-in require.
type operations struct{}

var _ gen.ServerInterface = operations{}

func (operations) Register(w http.ResponseWriter, r *http.Request) { unavailable(w, r) }

func (operations) StartSignIn(w http.ResponseWriter, r *http.Request, _ gen.StartSignInParams) {
	unavailable(w, r)
}

func (operations) CompleteSignIn(w http.ResponseWriter, r *http.Request, _ gen.CompleteSignInParams) {
	unavailable(w, r)
}

func (operations) SignOut(w http.ResponseWriter, r *http.Request) { unavailable(w, r) }

func (operations) GetMe(w http.ResponseWriter, r *http.Request) { unavailable(w, r) }

func (operations) Authenticate(w http.ResponseWriter, r *http.Request, _ gen.AuthenticateParams) {
	unavailable(w, r)
}

func (operations) GetKeys(w http.ResponseWriter, r *http.Request) { unavailable(w, r) }

func (operations) IssueWorkloadToken(w http.ResponseWriter, r *http.Request) { unavailable(w, r) }

func (operations) LookUpPrincipals(w http.ResponseWriter, r *http.Request) { unavailable(w, r) }

func (operations) ReceiveBackChannelLogout(w http.ResponseWriter, r *http.Request) { unavailable(w, r) }

func unavailable(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeProblem(w, r, http.StatusServiceUnavailable, gen.IdentityErrorCodeUnavailable, unavailableTitle)
}

// invalidParameter answers a request whose parameters do not match the contract. On the
// authentication endpoint it answers 503: a call that lacks or misforms a header that Edge always
// sends is Edge's defect (design section 05). The headers there that the client controls, the cookie,
// Origin and the trace context, are refused for nothing, so admission must decide on them by the
// cross-site and session rules instead, not reach this answer. Every other operation answers 400
// invalid_request, which says nothing about any account.
func invalidParameter(w http.ResponseWriter, r *http.Request, _ error) {
	if r.Pattern == authenticationPattern {
		unavailable(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeProblem(w, r, http.StatusBadRequest, gen.IdentityErrorCodeInvalidRequest, invalidRequestTitle)
}
