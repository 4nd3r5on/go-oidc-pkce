# go-oidc-pkce

Provider-agnostic OIDC Authorization Code Flow + PKCE for Go server-side apps.

Learning project, not maintained.

## What it does

Implements the login and callback flow — state (CSRF), nonce (replay), and PKCE.
See [GUIDE.md](GUIDE.md) for the full protocol walkthrough and [openapi/api.yml](openapi/api.yml) for the HTTP API spec.

## Interfaces you must implement

```go
// Single-use state store; Load must atomically delete the entry.
StateStore  // = StateSaver + StateLoader

// JIT user provisioning, keyed on (provider, sub).
UserUpserter[ClaimsT]

// Creates the application session (cookie, JWT, etc.).
SessionIssuer[SessionT]
```

See [interfaces.go](interfaces.go) for full signatures.

## Usage

```go
// 1. Discover provider metadata (hits /.well-known/openid-configuration).
provider, err := oidcpkce.NewProvider(ctx, oidcpkce.ProviderConfig{
    IssuerURL:    "https://your-issuer",
    ClientID:     "client-id",
    ClientSecret: "client-secret",
    RedirectURL:  "https://your-app/auth/callback",
    ProviderName: "my-provider",
    Scopes:       []string{"openid", "email", "profile"},
})

// 2. Wire up login and callback.
//    Use DefaultValidateRedirectURI (relative paths only) or supply a stricter allow-list.
login := oidcpkce.NewLogin(myStateStore, provider, oidcpkce.DefaultValidateRedirectURI)
callback := oidcpkce.NewCallback[oidcpkce.DefaultClaims, MySession](
    myStateStore, provider, myUserUpserter, mySessionIssuer,
)

// 3. Register HTTP handlers.
mux.Handle("/auth/login", &oidcpkce.LoginHandler{
    LoginInterface: login,
    HandleError:    oidcpkce.DefaultErrorHandlerFunc,
    HandleSuccess: func(w http.ResponseWriter, r *http.Request, redirectURL string) {
        http.Redirect(w, r, redirectURL, http.StatusFound)
    },
})
mux.Handle("/auth/callback", &oidcpkce.CallbackHandler[MySession]{
    CallbackInterface: callback,
    HandleError:       oidcpkce.DefaultErrorHandlerFunc,
    HandleSuccess: func(w http.ResponseWriter, r *http.Request, session MySession, redirectURL string) {
        // attach session to response, then redirect
        http.Redirect(w, r, redirectURL, http.StatusFound)
    },
})
```

Custom claims structs must satisfy `HasNonce` (`GetNonce() string`). `DefaultClaims` covers `sub`, `email`, `email_verified`, `name`, and `nonce`.

## Design notes

- No storage or session format opinions — all injected via interfaces.
- `StateStore.Load` must be atomic and destructive (prevents CSRF replay).
- `redirect_uri` is validated before state generation; override `ValidateRedirectURIFunc` for allow-list rules.
- Identity is keyed on `(provider, sub)`.

## Dependencies

- [`github.com/coreos/go-oidc`](https://github.com/coreos/go-oidc) — JWKS verification, discovery
- [`golang.org/x/oauth2`](https://pkg.go.dev/golang.org/x/oauth2) — code exchange, PKCE helpers
