package memory

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	oidcpkce "github.com/4nd3r5on/go-oidc-pkce"
)

// User is a minimal user record stored in memory.
type User struct {
	ID       string
	Provider string
	Claims   oidcpkce.DefaultClaims
}

// UserStore is an in-memory implementation of [oidcpkce.UserUpserter][oidcpkce.DefaultClaims].
// Identity is keyed on (provider, sub). Mutable claims (email, name) are synced on each login.
type UserStore struct {
	mu      sync.RWMutex
	byKey   map[string]*User // key: "provider\x00sub"
	counter atomic.Int64
}

func NewUserStore() *UserStore {
	return &UserStore{byKey: make(map[string]*User)}
}

// Upsert creates the user if absent and always syncs the latest claims.
// Returns the internal user ID.
func (s *UserStore) Upsert(_ context.Context, provider string, c oidcpkce.DefaultClaims) (string, error) {
	key := provider + "\x00" + c.Sub

	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.byKey[key]
	if !ok {
		id := fmt.Sprintf("usr_%d", s.counter.Add(1))
		u = &User{ID: id, Provider: provider}
		s.byKey[key] = u
	}
	u.Claims = c
	return u.ID, nil
}

// Get returns the user by internal ID. Useful in tests and handlers.
func (s *UserStore) Get(id string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.byKey {
		if u.ID == id {
			return u, true
		}
	}
	return nil, false
}
