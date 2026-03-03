# OIDC + PKCE. Integrating it to your app

| Parameter                        | Guards against                  | Verified by   | At what point        |
| -------------------------------- | ------------------------------- | ------------- | -------------------- |
| `state`                          | OAuth CSRF (forged callback)    | Your app      | On callback receipt  |
| `nonce`                          | ID token replay                 | Your app      | After token exchange |
| `code_verifier`/`code_challenge` | Authorization code interception | OIDC provider | During code exchange |

## `GET /auth/login`

1. Generate `state`: cryptographically random, >=128 bits entropy (e.g. 32 random bytes => base64url).
2. Generate `nonce`: same approach, completely independent. Never derive one from the other, never reuse.
3. Generate `code_verifier`: random, 43–128 chars, URL-safe alphabet (RFC 7636 §4.1).
4. Compute `code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))`: S256 method.
5. **Persist `state`, `nonce`, and `code_verifier`** in a signed HttpOnly cookie or server-side session. Short TTL (~10 min). These must survive the browser round-trip.
6. Build the authorization URL (`/authorize` on the provider) with: `response_type=code`, `client_id`, `redirect_uri` (exact match to registered URI), `scope` (minimum `openid`; `email`/`profile` add claims), `state`, `nonce`, `code_challenge`, `code_challenge_method=S256`.
7. Redirect the user.

**Failure modes:** storing `code_verifier` in browser memory/localStorage (XSS-exposed); reusing `state` or `nonce`; weak entropy.

## `GET /auth/callback`

### Validate the callback

1. Extract `state` from query params.
2. Load stored `state` from session/cookie.
3. If missing or mismatch => **hard abort**. 400, log it, do not proceed. This is CSRF.

### Exchange the code

4. Extract `code` from query params.
5. POST to `/token` endpoint: `grant_type=authorization_code`, `code`, `redirect_uri` (identical to login), `client_id`, `client_secret` (confidential clients), `code_verifier` (from session).
6. Provider hashes `code_verifier`, compares to stored `code_challenge`. On mismatch it rejects -- you'll get an error response. PKCE is verified here, on the provider side.

### Validate the ID token

7. Token response contains `id_token` (JWT), `access_token`, optionally `refresh_token`.
8. Verify the `id_token`:
   - **Signature**: against provider's JWKS (cache with rotation support, fetch from `/.well-known/openid-configuration`).
   - **`iss`**: must match your provider URL exactly.
   - **`aud`**: must contain your `client_id`.
   - **`exp`**: must be in the future.
   - **`iat`**: within clock skew tolerance (e.g. ±60s).
   - **`nonce` claim**: extract from token payload, compare to stored nonce. Mismatch = replay attack, hard abort.
7. Extract claims. What's present depends on requested scopes: `openid` => `sub`; `email` => `email`, `email_verified`; `profile` => `name`, `given_name`, etc.

### JIT provisioning

10. Look up user by `sub` (stable, preferred). Looking up by email or other attributes might also be useful if u want avoid creating new users for each auth method.
11. No user found => create one from claims.
12. User found, claims differ => decide whether to sync (e.g. updated email).

### Issue your session, clean up

13. Create your app's session (your format -- JWT, opaque token, server-side session, signature key, anything).
14. Set session cookie: `HttpOnly`, `Secure`, `SameSite=Lax` (or `Strict` if your app allows same-origin flows only).
15. **Invalidate `state`/`nonce`/`code_verifier`** from storage -- single-use, window closed.
16. Redirect to app (stored pre-login destination, or default landing).

**Failure modes:** skipping `nonce` check => replay undetected; skipping `aud` check => token for another client accepted; not invalidating after use => replay window stays open; keying users on `email` => identity breaks on provider-side email change.

## Storage options for `state`/`nonce`/`code_verifier`

| Method | Pros | Cons |
|---|---|---|
| Signed HttpOnly cookie | Stateless server, load-balancer safe | Size limit, signing key required |
| Server-side session (Redis/DB) | Arbitrary size, revocable | Requires session store |
| Encrypted HttpOnly cookie | Stateless, opaque to client | Size limit, key management |

Never: unsigned cookie, localStorage, JS closure.

## Scope/claims cheatsheet

| Scope               | Claims                                                   |
| ------------------- | -------------------------------------------------------- |
| `openid` (required) | `sub`, `iss`, `aud`, `exp`, `iat`, `nonce`               |
| `email`             | `email`, `email_verified`                                |
| `profile`           | `name`, `given_name`, `family_name`, `picture`, `locale` |
| `phone`             | `phone_number`, `phone_number_verified`                  |

Provider-specific scopes (roles, groups, etc)
https://auth0.com/docs/get-started/apis/scopes/openid-connect-scopes
https://docs.goauthentik.io/users-sources/sources/protocols/oauth/

## Implementation checklist
state: fresh per login, verified on callback, single-use
nonce: fresh per login, verified inside ID token, single-use
code_verifier: stored server-side, sent at token exchange, single-use
code_challenge = BASE64URL(SHA256(code_verifier)), method=S256
ID token signature verified against JWKS
iss, aud, exp, iat all checked
nonce claim in token matched against stored nonce
All three values invalidated after use
User identity keyed on sub, not email
Session cookie: HttpOnly, Secure, SameSite

**Source**: auth0.com/docs
