// Package oidcpkce implements a provider-agnostic OpenID Connect (OIDC)
// Authorization Code Flow with PKCE for server-side web applications.
//
// The implementation follows:
//
//   - OAuth 2.0 Authorization Code Grant (RFC 6749)
//   - Proof Key for Code Exchange (PKCE) (RFC 7636)
//   - OpenID Connect Core 1.0
//
// # Security model
//
// The login flow enforces three independent protections:
//
//  1. state  — CSRF protection, validated on callback
//  2. nonce  — ID token replay protection, validated inside claims
//  3. PKCE   — Authorization code interception protection
//
// All three values are single-use and must be invalidated after
// the callback completes.
//
// Flow order
//
//  1. Generate state, nonce, code_verifier
//  2. Persist LoginState server-side
//  3. Redirect to provider authorization endpoint
//  4. Exchange authorization code (PKCE verified by provider)
//  5. Verify ID token signature and standard claims
//  6. Verify nonce
//  7. JIT provision user (keyed on provider + sub)
//  8. Issue application session
//
// Design principles
//
//   - Provider-agnostic (works with any compliant OIDC provider)
//   - No persistence assumptions (StateStore, UserStore, SessionIssuer are interfaces)
//   - Identity keyed on (provider, sub), never on email
//   - Safe for concurrent use after construction
//
// The package does not implement storage, user management,
// or session format directly. Those concerns are injected via interfaces.
package oidcpkce
