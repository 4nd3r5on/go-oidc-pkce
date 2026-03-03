package oidcpkce

import (
	"net/http"

	"golang.org/x/oauth2"
)

// HandleLogin — GET /auth/login
//
// Generates state, nonce, and code_verifier independently.
// Stores all three server-side before the redirect; they must survive the round-trip.
func (p *Provider[ClaimsT]) HandleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := secureToken()
	if err != nil {
		http.Error(w, "entropy failure", http.StatusInternalServerError)
		return
	}
	nonce, err := secureToken()
	if err != nil {
		http.Error(w, "entropy failure", http.StatusInternalServerError)
		return
	}
	// oauth2.GenerateVerifier produces a 32-byte random, base64url-encoded string (RFC 7636 §4.1).
	codeVerifier := oauth2.GenerateVerifier()

	ls := LoginState{
		State:        state,
		Nonce:        nonce,
		CodeVerifier: codeVerifier,
		ReturnURL:    r.URL.Query().Get("return_url"),
	}
	if err := p.states.Save(r.Context(), ls); err != nil {
		http.Error(w, "state persistence failed", http.StatusInternalServerError)
		return
	}

	authURL := p.oauth2Cfg.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("nonce", nonce),   // ID token replay protection
		oauth2.S256ChallengeOption(codeVerifier), // PKCE: code_challenge + code_challenge_method=S256
	)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// HandleCallback — GET /auth/callback
//
// Step order mirrors the doc: state → exchange → id_token sig → nonce → JIT → session.
func (p *Provider[ClaimsT]) HandleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	// 1. Load + atomically invalidate stored state — single-use window.
	//    Missing or already-consumed key = CSRF or replay; hard abort.
	ls, err := p.states.Load(r.Context(), q.Get("state"))
	if err != nil {
		http.Error(w, "invalid or expired state", http.StatusBadRequest)
		return
	}

	// 2. Exchange code → tokens. Provider verifies code_challenge here (PKCE).
	token, err := p.oauth2Cfg.Exchange(
		r.Context(),
		q.Get("code"),
		oauth2.VerifierOption(ls.CodeVerifier),
	)
	if err != nil {
		http.Error(w, "token exchange failed", http.StatusInternalServerError)
		return
	}

	// 3. Extract raw ID token from token response.
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "missing id_token in token response", http.StatusInternalServerError)
		return
	}

	// 4. Verify ID token: signature (JWKS), iss, aud, exp, iat (go-oidc).
	idToken, err := p.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, "id_token verification failed", http.StatusUnauthorized)
		return
	}

	// 5. Extract claims + verify nonce — replay attack protection.
	//    Skipping this check leaves replay undetected even with valid state.
	var idClaims ClaimsT
	if err := idToken.Claims(&idClaims); err != nil {
		http.Error(w, "claims extraction failed", http.StatusInternalServerError)
		return
	}
	if idClaims.GetNonce() != ls.Nonce {
		// Nonce mismatch: ID token issued for a different flow or replayed.
		http.Error(w, "nonce mismatch", http.StatusUnauthorized)
		return
	}

	// 6. JIT provisioning — keyed on sub (stable), not email (mutable).
	userID, err := p.users.Upsert(r.Context(), p.providerName, idClaims)
	if err != nil {
		http.Error(w, "user provisioning failed", http.StatusInternalServerError)
		return
	}

	// 7. Issue application session (format is SessionIssuer's concern).
	if err := p.sessions.Issue(r.Context(), w, userID); err != nil {
		http.Error(w, "session issuance failed", http.StatusInternalServerError)
		return
	}

	returnURL := ls.ReturnURL
	if returnURL == "" {
		returnURL = "/"
	}
	http.Redirect(w, r, returnURL, http.StatusFound)
}
