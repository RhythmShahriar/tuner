// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package checkpack

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// SigName is the release asset holding the Ed25519 signature of SumsName,
// base64 on one line.
const SigName = SumsName + ".sig"

// trustedKeys are the base64 Ed25519 public keys a pack's checksum file
// may be signed with. The private half lives only in the repository's
// TUNER_PACK_SIGNING_KEY Actions secret.
//
// To rotate, add the new key here and release a binary, switch the secret
// to the new private key and remove the old key in a later release once
// binaries that only trust it are rare. `go run ./internal/packbuild
// -gen-key` prints a new pair.
//
// While the list is empty this build trusts no pack and always uses its
// built-in checks.
var trustedKeys = []string{}

// ErrNoTrustedKeys means this build embeds no signing key, so it cannot
// verify any pack and never fetches one.
var ErrNoTrustedKeys = errors.New("this build trusts no check pack signing key")

// errSignature wraps every signature failure. A bad or missing signature
// is not cached as a verdict: during an upload the four assets change one
// by one, so a client can briefly see new sums with the old signature.
var errSignature = errors.New("check pack signature")

// TrustedKeys parses the embedded public keys.
func TrustedKeys() ([]ed25519.PublicKey, error) {
	keys := make([]ed25519.PublicKey, 0, len(trustedKeys))
	for i, s := range trustedKeys {
		k, err := ParsePublicKey(s)
		if err != nil {
			return nil, fmt.Errorf("trusted key %d: %w", i, err)
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// ParsePublicKey decodes a base64 Ed25519 public key.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key is %d bytes, want %d", len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

// ParsePrivateKey decodes a base64 Ed25519 private key: either the 32-byte
// seed or the 64-byte form Go's crypto/ed25519 uses.
func ParsePrivateKey(s string) (ed25519.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, errors.New("private key is not valid base64")
	}
	switch len(b) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(b), nil
	case ed25519.PrivateKeySize:
		k := ed25519.PrivateKey(b)
		// The second half is the public key; a mismatch means a corrupt key
		// that would make signatures nobody can verify.
		if !ed25519.NewKeyFromSeed(k.Seed()).Equal(k) {
			return nil, errors.New("private key is corrupt")
		}
		return k, nil
	}
	return nil, fmt.Errorf("private key is %d bytes, want %d or %d", len(b), ed25519.SeedSize, ed25519.PrivateKeySize)
}

// Sign returns the SigName contents for a checksum file.
func Sign(sums []byte, key ed25519.PrivateKey) []byte {
	return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(key, sums)) + "\n")
}

// verifySig checks that sig is a signature of sums by one of keys.
func verifySig(sums, sig []byte, keys []ed25519.PublicKey) error {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || len(raw) != ed25519.SignatureSize {
		return fmt.Errorf("%w: %s is malformed", errSignature, SigName)
	}
	for _, k := range keys {
		if ed25519.Verify(k, sums, raw) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s is not signed by a trusted key", errSignature, SumsName)
}
