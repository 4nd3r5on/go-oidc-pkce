package oidcpkce

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
)

const (
	StateLen = 32
	NonceLen = 32
)

var (
	ErrStatePersistenceFailed = errors.New("state persistence failed")
	ErrEntropy                = errors.New("entropy failure")
	ErrInvalidRedirectURI     = errors.New("invalid redirect_uri")
)

// getToken returns random bytes encoded as base64url (no padding).
func getToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ValidateRedirectURIFunc validates the redirect_uri query parameter before
// login state is generated. Return [ErrInvalidRedirectURI] to reject the value.
// Use [DefaultValidateRedirectURI] or supply a stricter allow-list implementation.
type ValidateRedirectURIFunc func(ctx context.Context, uri string) error

// DefaultValidateRedirectURI rejects any URI that is not a relative path —
// i.e. anything with a host or scheme component — to prevent open redirects.
// Empty string is accepted (the callback will fall back to "/").
//
// Leading backslashes are explicitly rejected: url.Parse does not normalise
// them, but browsers do (\\evil.com → https://evil.com), so they bypass the
// host/scheme check without this guard.
func DefaultValidateRedirectURI(_ context.Context, uri string) error {
	if strings.HasPrefix(uri, "\\") {
		return ErrInvalidRedirectURI
	}
	u, err := url.Parse(uri)
	if err != nil || u.Host != "" || u.Scheme != "" {
		return ErrInvalidRedirectURI
	}
	return nil
}

// Login handles GET /auth/login.
//
// Validates redirect_uri, then generates state, nonce, and code_verifier
// independently. Persists all values server-side before the redirect so they
// survive the browser round-trip.
type Login struct {
	state    StateSaver
	provider AuthCodeURLGetter

	validateRedirectURI ValidateRedirectURIFunc
}

func NewLogin(
	state StateSaver,
	provider AuthCodeURLGetter,
	validateRedirectURI ValidateRedirectURIFunc,
) *Login {
	return &Login{
		state:               state,
		provider:            provider,
		validateRedirectURI: validateRedirectURI,
	}
}

func (l *Login) Login(ctx context.Context, redirectURI string) (string, error) {
	if redirectURI != "" {
		err := l.validateRedirectURI(ctx, redirectURI)
		if err != nil {
			return "", errors.Join(ErrInvalidRedirectURI, err)
		}
	}

	state, err := getToken(StateLen)
	if err != nil {
		return "", errors.Join(ErrEntropy, err)
	}
	nonce, err := getToken(NonceLen)
	if err != nil {
		return "", errors.Join(ErrEntropy, err)
	}

	// oauth2.GenerateVerifier produces a 32-byte random, base64url-encoded string (RFC 7636 §4.1).
	codeVerifier := oauth2.GenerateVerifier()

	ls := LoginState{
		State:        state,
		Nonce:        nonce,
		CodeVerifier: codeVerifier,
		RedirectURI:  redirectURI,
	}
	if err := l.state.Save(ctx, ls); err != nil {
		return "", errors.Join(ErrStatePersistenceFailed, err)
	}
	authURL := l.provider.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("nonce", nonce),   // ID token replay protection
		oauth2.S256ChallengeOption(codeVerifier), // PKCE: code_challenge + code_challenge_method=S256
	)

	return authURL, nil
}
