// Package signing holds Identity's two signing keys, one for internal tokens and one for workload
// tokens, each an Ed25519 key that reaches Identity as a file (ADR 0020, ADR 0052), and signs tokens
// with them as JSON Web Tokens.
package signing

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sync/atomic"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/ancyloce/contelys-cloud-identity/internal/application/tokens"
)

// The issuer and the audience of every internal token, fixed in Identity's contract (design section
// 05), and the type that tells an internal token from a workload token.
const (
	issuer           = "urn:contelys:identity"
	internalAudience = "urn:contelys:domain-services"
	internalType     = "internal+jwt"
)

// Keys are the two signing keys, loaded from their files on first use.
type Keys struct {
	internalFile, workloadFile string
	loaded                     atomic.Pointer[pair]
}

// pair is the loaded keys, with the signer of internal tokens and the ID of its key.
type pair struct {
	internal, workload ed25519.PrivateKey
	internalID         string
	internalSigner     jose.Signer
}

var _ tokens.Signer = (*Keys)(nil)

// NewKeys returns the keys in internalFile and workloadFile, which are loaded by the first use that
// finds both.
func NewKeys(internalFile, workloadFile string) *Keys {
	return &Keys{internalFile: internalFile, workloadFile: workloadFile}
}

// Check is the readiness signal of the signing keys: both are loaded. Until they are, each call reads
// the files again, so that keys that arrive after the start make the instance ready without a
// restart.
func (k *Keys) Check(context.Context) error {
	_, err := k.current()
	return err
}

// SignInternal signs an internal token, with typ internal+jwt and the kid of the internal key.
func (k *Keys) SignInternal(token tokens.Internal) (string, error) {
	keys, err := k.current()
	if err != nil {
		return "", err
	}
	standard := jwt.Claims{
		Issuer:   issuer,
		Audience: jwt.Audience{internalAudience},
		Subject:  token.Principal,
		ID:       token.RequestID,
		IssuedAt: jwt.NewNumericDate(token.IssuedAt),
		Expiry:   jwt.NewNumericDate(token.Expiry),
	}
	private := struct {
		Session          string `json:"sid"`
		AuthorityVersion int64  `json:"authority_version"`
	}{token.Session, token.AuthorityVersion}
	return jwt.Signed(keys.internalSigner).Claims(standard).Claims(private).Serialize()
}

// PublicKeys are the keys of the key set: the key that verifies internal tokens. The workload key
// joins it with the workload tokens that it signs.
func (k *Keys) PublicKeys() ([]tokens.PublicKey, error) {
	keys, err := k.current()
	if err != nil {
		return nil, err
	}
	return []tokens.PublicKey{{ID: keys.internalID, Key: keys.internal.Public().(ed25519.PublicKey)}}, nil
}

// current returns the loaded keys, and loads them when they are not loaded yet.
func (k *Keys) current() (*pair, error) {
	if keys := k.loaded.Load(); keys != nil {
		return keys, nil
	}
	internal, err := read(k.internalFile)
	if err != nil {
		return nil, fmt.Errorf("the internal signing key: %w", err)
	}
	workload, err := read(k.workloadFile)
	if err != nil {
		return nil, fmt.Errorf("the workload signing key: %w", err)
	}
	id, err := keyID(internal.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.EdDSA, Key: jose.JSONWebKey{Key: internal, KeyID: id}},
		(&jose.SignerOptions{}).WithType(internalType))
	if err != nil {
		return nil, err
	}
	k.loaded.CompareAndSwap(nil, &pair{internal: internal, workload: workload, internalID: id, internalSigner: signer})
	return k.loaded.Load(), nil
}

// keyID names a public key by its thumbprint of RFC 7638, so that the same key keeps its ID on every
// instance without a setting.
func keyID(public ed25519.PublicKey) (string, error) {
	thumbprint, err := (&jose.JSONWebKey{Key: public}).Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

// read reads an Ed25519 private key in PKCS #8 PEM.
func read(path string) (ed25519.PrivateKey, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(content)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("no PKCS #8 private key in PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ed, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("a %T, not an Ed25519 key", key)
	}
	return ed, nil
}
