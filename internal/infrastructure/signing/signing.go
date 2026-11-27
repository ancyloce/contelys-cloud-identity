// Package signing holds Identity's two signing keys, one for internal tokens and one for workload
// tokens, each an Ed25519 key that reaches Identity as a file (ADR 0020, ADR 0052).
package signing

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
)

// Keys are the two signing keys, loaded from their files.
type Keys struct {
	internalFile, workloadFile string
	loaded                     atomic.Pointer[pair]
}

type pair struct {
	internal, workload ed25519.PrivateKey
}

// NewKeys returns the keys in internalFile and workloadFile, which are loaded by the first Check that
// finds both.
func NewKeys(internalFile, workloadFile string) *Keys {
	return &Keys{internalFile: internalFile, workloadFile: workloadFile}
}

// Check is the readiness signal of the signing keys: both are loaded. Until they are, each call reads
// the files again, so that keys that arrive after the start make the instance ready without a
// restart.
func (k *Keys) Check(context.Context) error {
	if k.loaded.Load() != nil {
		return nil
	}
	internal, err := read(k.internalFile)
	if err != nil {
		return fmt.Errorf("the internal signing key: %w", err)
	}
	workload, err := read(k.workloadFile)
	if err != nil {
		return fmt.Errorf("the workload signing key: %w", err)
	}
	k.loaded.CompareAndSwap(nil, &pair{internal: internal, workload: workload})
	return nil
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
