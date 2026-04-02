package oidcpkce

import (
	"context"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

// StateSaver persists a LoginState, keyed by LoginState.State.
type StateSaver interface {
	Save(ctx context.Context, s LoginState) error
}

// StateLoader retrieves a LoginState by its state key.
type StateLoader interface {
	// Load retrieves and immediately invalidates the entry (single-use).
	Load(ctx context.Context, stateKey string) (LoginState, error)
}

// StateStore persists LoginState for the ~10 min login window.
// Load must be atomic and destructive: a second call with the same key returns ErrStateNotFound.
// Implementations: signed HttpOnly cookie, Redis with DEL-after-GET, DB row with used_at.
type StateStore interface {
	StateSaver
	StateLoader
}

// UserUpserter handles JIT provisioning. Identity is keyed on (provider, sub).
// Implementations decide whether to sync mutable claims (e.g. updated email).
type UserUpserter[ClaimsT any] interface {
	// Upsert creates the user if absent, optionally syncs changed claims, returns internal user ID.
	Upsert(ctx context.Context, provider string, c ClaimsT) (userID string, err error)
}

// SessionIssuer creates the application session and writes it to the response
// (e.g. sets a signed HttpOnly cookie or issues a JWT).
type SessionIssuer[SessionT any] interface {
	Issue(ctx context.Context, userID string) (SessionT, error)
}

// HasNonce is implemented by any claims type that carries a nonce field.
// It is used by [Callback] to verify the nonce against the stored LoginState.
type HasNonce interface {
	GetNonce() string
}

type IDTokenVerifier interface {
	Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error)
}

type IDTokenExchanger interface {
	Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error)
}

type AuthCodeURLGetter interface {
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
}

type ProviderInterface interface {
	Name() string
	IDTokenVerifier
	IDTokenExchanger
	AuthCodeURLGetter
}

type LoginInterface interface {
	Login(ctx context.Context, redirectURI string) (string, error)
}

type CallbackInterface[SessionT any] interface {
	Callback(
		ctx context.Context,
		state string,
		code string,
	) (SessionT, string, error)
}
