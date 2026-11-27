package httpapi

// The server stubs are generated from Identity's contract in the contracts module at the version that
// go.mod requires, by oapi-codegen at a pinned version, and committed under gen/ (Identity ADR 0009).
// Run go generate ./... with GOWORK=off to regenerate them.
//
//go:generate sh -c "go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.9.0 -config identity.oapi-codegen.yaml \"$(go list -m -f '{{.Dir}}' github.com/ancyloce/contelys-cloud-contracts)/openapi/identity/openapi.yaml\""
