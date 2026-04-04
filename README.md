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

## Demo server

`cmd/demo` is a minimal runnable server that wires the library with the in-memory implementations from `pkg/memory`.

### Routes

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Returns JSON with session/user info when authenticated, `{"authenticated":false}` otherwise |
| `GET` | `/auth/login` | Redirects to the OIDC provider; accepts `?redirect_uri=` for post-login destination |
| `GET` | `/auth/callback` | Exchanges the authorization code, sets a `session_id` cookie, redirects |
| `POST` | `/auth/logout` | Deletes the server-side session, clears the cookie, returns `{"ok":true}` |

### Configuration

All config is via environment variables.

| Variable | Required | Default | Description |
|---|---|---|---|
| `OIDC_ISSUER_URL` | yes | — | Provider discovery URL (e.g. `https://accounts.google.com`) |
| `OIDC_CLIENT_ID` | yes | — | OAuth2 client ID |
| `OIDC_CLIENT_SECRET` | yes | — | OAuth2 client secret |
| `DEMO_EXTERNAL_URL` | yes | — | Base URL of this server, used to build the callback URL (e.g. `http://localhost:8080`) |
| `OIDC_PROVIDER_NAME` | no | `oidc` | Label stored on the user record |
| `DEMO_ADDR` | no | `:8080` | Listen address |
| `DEMO_SESSION_TTL` | no | `24h` | Session lifetime as a Go duration string (e.g. `1h30m`) |

### Running

Register `<DEMO_EXTERNAL_URL>/auth/callback` as an allowed redirect URI in your provider, then:

```sh
export OIDC_ISSUER_URL=https://your-issuer
export OIDC_CLIENT_ID=your-client-id
export OIDC_CLIENT_SECRET=your-client-secret
export DEMO_EXTERNAL_URL=http://localhost:8080

go run ./cmd/demo
```

Then `GET http://localhost:8080/` to check your session status.

## Design notes

- No storage or session format opinions — all injected via interfaces.
- `StateStore.Load` must be atomic and destructive (prevents CSRF replay).
- `redirect_uri` is validated before state generation; override `ValidateRedirectURIFunc` for allow-list rules.
- Identity is keyed on `(provider, sub)`.

## Tests

```
go test ./...
```

### What is tested

**`DefaultValidateRedirectURI`** (`login_test.go`) — the only unit-testable logic with real value:
relative paths, absolute URLs, protocol-relative (`//evil.com`), dangerous schemes
(`javascript:`, `data:`), and backslash-prefixed URIs (`\\evil.com`), which `url.Parse`
doesn't catch but browsers normalise to `https://evil.com`.

### What is not tested and why

**`Login` and `Callback`** are almost entirely wiring between injected interfaces. Unit tests
for them would mock `StateSaver`, `ProviderInterface`, `UserUpserter`, and `SessionIssuer`,
then assert each was called in order — which mirrors the code without testing any real logic.
Such tests break on minor refactors and catch nothing that a code review wouldn't.

The non-trivial behaviour in both structs (nonce comparison, state invalidation, PKCE
verification) lives inside the injected dependencies or on the provider side. That behaviour
belongs in integration tests against a real OIDC provider, not in mocked unit tests.

## Dependencies

- [`github.com/coreos/go-oidc`](https://github.com/coreos/go-oidc) — JWKS verification, discovery
- [`golang.org/x/oauth2`](https://pkg.go.dev/golang.org/x/oauth2) — code exchange, PKCE helpers
