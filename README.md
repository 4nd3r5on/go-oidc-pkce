# go-oidc-pkce

Provider-agnostic OIDC Authorization Code Flow + PKCE for Go server-side apps.

Learning project, not maintianed.

## What it does

Implements the login flow. More about the flow in
[Read the GUIDE.md](GUIDE.md)

See [api.yml](api.yml) for the OpenAPI spec.

## Interfaces you must implement

```go
// Single-use state store (load must atomically delete)
StateStore

// JIT user provisioning keyed on (provider, sub)
UserStore[ClaimsT]

// Writes session to response (cookie, JWT, etc.)
SessionIssuer
```

Check [Interfaces file](interfaces.go)

## Usage

```go
provider, err := oidcpkce.NewProvider[oidcpkce.DefaultClaims](
    ctx,
    "https://your-issuer",
    clientID, clientSecret, redirectURL,
    "my-provider",
    myStateStore,
    myUserStore,
    mySessionIssuer,
)
if err != nil {
  fmt.Fatalf("error creating OIDC provider: %v", err)
}

mux.HandleFunc("/auth/login",    provider.HandleLogin)
mux.HandleFunc("/auth/callback", provider.HandleCallback)
```

Custom claims must satisfy `HasNonce` (`GetNonce() string`).

## Design notes

- No storage or session format opinions — all injected
- `StateStore.Load` must be atomic and destructive (prevents replay)

## Dependencies

- [`github.com/coreos/go-oidc`](https://github.com/coreos/go-oidc) -- JWKS verification, discovery
- [`golang.org/x/oauth2`](https://pkg.go.dev/golang.org/x/oauth2) -- code exchange, PKCE helpers
