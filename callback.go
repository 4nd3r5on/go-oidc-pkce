package oidcpkce

import (
	"context"
	"errors"

	"golang.org/x/oauth2"
)

var (
	ErrMissingIDToken            = errors.New("missing id_token in token response")
	ErrIDTokenVerificationFailed = errors.New("id_token verification failed")
	ErrClaimsExtractionFailed    = errors.New("claims extraction failed")
	ErrNonceMismatch             = errors.New("nonce mismatch")
	ErrUserUpsertFailed          = errors.New("user upsert failed")
	ErrSessionIssuanceFailed     = errors.New("session issuance failed")
	ErrTokenExchangeFailed       = errors.New("token exchange failed")
	ErrInvalidState              = errors.New("invalid or expired state")
	ErrStateMissing              = errors.New("state parameter missing")
	ErrCodeMissing               = errors.New("code parameter missing")
)

// Callback — GET /auth/callback
//
// Step order mirrors the doc: state → exchange → id_token sig → nonce → JIT → session.
type Callback[ClaimsT HasNonce, SessionT any] struct {
	state    StateLoader
	provider ProviderInterface
	users    UserUpserter[ClaimsT]
	session  SessionIssuer[SessionT]
}

func NewCallback[ClaimsT HasNonce, SessionT any](
	state StateLoader,
	provider ProviderInterface,
	users UserUpserter[ClaimsT],
	session SessionIssuer[SessionT],
) *Callback[ClaimsT, SessionT] {
	return &Callback[ClaimsT, SessionT]{
		state:    state,
		provider: provider,
		users:    users,
		session:  session,
	}
}

func (c *Callback[ClaimsT, SessionT]) Callback(
	ctx context.Context,
	state string,
	code string,
) (SessionT, string, error) {
	var zeroSession SessionT

	if state == "" {
		return zeroSession, "", ErrStateMissing
	}
	if code == "" {
		return zeroSession, "", ErrCodeMissing
	}

	// 1. Load + atomically invalidate stored state — single-use window.
	//    Missing or already-consumed key = CSRF or replay; hard abort.
	ls, err := c.state.Load(ctx, state)
	if err != nil {
		return zeroSession, "", errors.Join(ErrInvalidState, err)
	}

	// 2. Exchange code → tokens. Provider verifies code_challenge here (PKCE).
	token, err := c.provider.Exchange(
		ctx,
		code,
		oauth2.VerifierOption(ls.CodeVerifier),
	)
	if err != nil {
		return zeroSession, "", errors.Join(ErrTokenExchangeFailed, err)
	}

	// 3. Extract raw ID token from token response.
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return zeroSession, "", ErrMissingIDToken
	}

	// 4. Verify ID token: signature (JWKS), iss, aud, exp, iat (go-oidc).
	idToken, err := c.provider.Verify(ctx, rawIDToken)
	if err != nil {
		return zeroSession, "", errors.Join(ErrIDTokenVerificationFailed, err)
	}

	// 5. Extract claims + verify nonce — replay attack protection.
	//    Skipping this check leaves replay undetected even with valid state.
	var idClaims ClaimsT
	if err = idToken.Claims(&idClaims); err != nil {
		return zeroSession, "", errors.Join(ErrClaimsExtractionFailed, err)
	}
	if idClaims.GetNonce() != ls.Nonce {
		// Nonce mismatch: ID token issued for a different flow or replayed.
		return zeroSession, "", ErrNonceMismatch
	}

	// 6. JIT provisioning — keyed on sub (stable), not email (mutable).
	userID, err := c.users.Upsert(ctx, c.provider.Name(), idClaims)
	if err != nil {
		return zeroSession, "", errors.Join(ErrUserUpsertFailed, err)
	}

	// 7. Issue application session (format is SessionIssuer's concern).
	session, err := c.session.Issue(ctx, userID)
	if err != nil {
		return zeroSession, "", errors.Join(ErrSessionIssuanceFailed, err)
	}

	redirectURL := ls.RedirectURI
	if redirectURL == "" {
		redirectURL = "/"
	}
	return session, redirectURL, nil
}
