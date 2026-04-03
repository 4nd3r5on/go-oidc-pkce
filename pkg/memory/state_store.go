package memory

import (
	"context"
	"sync"

	oidcpkce "github.com/4nd3r5on/go-oidc-pkce"
)

// StateStore is an in-memory implementation of [oidcpkce.StateStore].
// Load is atomic and destructive: a second call with the same key returns [oidcpkce.ErrStateNotFound].
type StateStore struct {
	mu     sync.Mutex
	states map[string]oidcpkce.LoginState
}

func NewStateStore() *StateStore {
	return &StateStore{states: make(map[string]oidcpkce.LoginState)}
}

func (s *StateStore) Save(_ context.Context, state oidcpkce.LoginState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[state.State] = state
	return nil
}

// Load retrieves and immediately deletes the entry (single-use).
func (s *StateStore) Load(_ context.Context, stateKey string) (oidcpkce.LoginState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ls, ok := s.states[stateKey]
	if !ok {
		return oidcpkce.LoginState{}, oidcpkce.ErrStateNotFound
	}
	delete(s.states, stateKey)
	return ls, nil
}
