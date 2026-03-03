package oidcpkce

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// secureToken returns 32 random bytes encoded as base64url (no padding).
// 32 bytes = 256 bits of entropy, well above the ≥128 bit minimum.
func secureToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// s256Challenge computes BASE64URL(SHA256(ASCII(verifier))) per RFC 7636 §4.2.
// Exposed for use in tests / manual flows; oauth2.S256ChallengeOption calls the
// equivalent internally.
func s256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
