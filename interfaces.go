package oidcpkce

import (
	"context"
	"net/http"
)

// StateStore persists LoginState for the ~10 min login window.
// Load must be atomic and destructive: a second call with the same key returns ErrStateNotFound.
// Implementations: signed HttpOnly cookie, Redis with DEL-after-GET, DB row with used_at.
type StateStore interface {
	Save(ctx context.Context, s LoginState) error
	// Load retrieves and immediately invalidates the entry (single-use).
	Load(ctx context.Context, stateKey string) (LoginState, error)
}

// UserStore handles JIT provisioning. Identity is keyed on (provider, sub).
// Implementations decide whether to sync mutable claims (e.g. updated email).
type UserStore[ClaimsT any] interface {
	// Upsert creates the user if absent, optionally syncs changed claims, returns internal user ID.
	Upsert(ctx context.Context, provider string, c ClaimsT) (userID string, err error)
}

// SessionIssuer creates the application session and writes it to the response
// (e.g. sets a signed HttpOnly cookie or issues a JWT).
type SessionIssuer interface {
	Issue(ctx context.Context, w http.ResponseWriter, userID string) error
}

type HasNonce interface {
	GetNonce() string
}
