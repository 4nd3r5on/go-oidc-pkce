package memory

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// Session is the application session issued after a successful OIDC callback.
type Session struct {
	ID        string
	UserID    string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// SessionStore is an in-memory implementation of [oidcpkce.SessionIssuer][Session].
// It also stores issued sessions so handlers can look them up by ID.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	ttl      time.Duration
}

// NewSessionStore creates a SessionStore with the given session TTL.
func NewSessionStore(ttl time.Duration) *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*Session),
		ttl:      ttl,
	}
}

// Issue creates a new Session for the given userID and stores it.
func (s *SessionStore) Issue(_ context.Context, userID string) (Session, error) {
	id, err := newSessionID()
	if err != nil {
		return Session{}, fmt.Errorf("generate session id: %w", err)
	}
	now := time.Now()
	sess := &Session{
		ID:        id,
		UserID:    userID,
		IssuedAt:  now,
		ExpiresAt: now.Add(s.ttl),
	}
	s.mu.Lock()
	s.sessions[id] = sess
	s.mu.Unlock()
	return *sess, nil
}

// Get retrieves a session by ID. Returns (zero, false) when not found or expired.
func (s *SessionStore) Get(id string) (Session, bool) {
	s.mu.RLock()
	sess, ok := s.sessions[id]
	s.mu.RUnlock()
	if !ok || time.Now().After(sess.ExpiresAt) {
		return Session{}, false
	}
	return *sess, true
}

// Delete removes a session (logout).
func (s *SessionStore) Delete(id string) {
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
}

func newSessionID() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
