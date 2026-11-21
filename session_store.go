package keycloakopenid

import (
	"sync"
	"time"
)

type Session struct {
	mu               sync.Mutex
	AccessToken      string
	RefreshToken     string
	ExpiresAt        time.Time
	RefreshExpiresAt time.Time
}

func (s *Session) snapshot() (accessToken, refreshToken string, expiresAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.AccessToken, s.RefreshToken, s.ExpiresAt
}

// expired reports whether the session can neither authorize nor be renewed.
func (s *Session) expired(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	accessExpired := !s.ExpiresAt.IsZero() && now.After(s.ExpiresAt)
	if s.RefreshToken == "" {
		return accessExpired
	}
	return accessExpired && !s.RefreshExpiresAt.IsZero() && now.After(s.RefreshExpiresAt)
}

var (
	sharedStoresMu sync.Mutex
	sharedStores   = map[string]*SessionStore{}
)

// sharedSessionStore returns the process-wide store for one Keycloak client.
// Traefik creates a middleware instance per router and recreates every
// instance on each configuration reload, so sessions must outlive instances.
func sharedSessionStore(key string) *SessionStore {
	sharedStoresMu.Lock()
	defer sharedStoresMu.Unlock()
	store, ok := sharedStores[key]
	if !ok {
		store = NewSessionStore()
		sharedStores[key] = store
	}
	return store
}

type SessionStore struct {
	sessions map[string]*Session
	mu       sync.RWMutex
}

func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*Session),
	}
}

func (s *SessionStore) Set(sessionID string, session *Session) {
	s.evictExpired(time.Now())
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sessionID] = session
}

// evictExpired drops sessions that will never be requested again. Session
// locks are taken outside the store lock because a renewal holds its session
// lock while calling Keycloak.
func (s *SessionStore) evictExpired(now time.Time) {
	s.mu.RLock()
	candidates := make(map[string]*Session, len(s.sessions))
	for id, session := range s.sessions {
		candidates[id] = session
	}
	s.mu.RUnlock()

	for id, session := range candidates {
		if !session.expired(now) {
			delete(candidates, id)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for id, session := range candidates {
		if s.sessions[id] == session {
			delete(s.sessions, id)
		}
	}
}

func (s *SessionStore) Get(sessionID string) (*Session, bool) {
	s.mu.RLock()
	session, exists := s.sessions[sessionID]
	s.mu.RUnlock()
	if !exists {
		return nil, false
	}
	if session.expired(time.Now()) {
		s.mu.Lock()
		delete(s.sessions, sessionID)
		s.mu.Unlock()
		return nil, false
	}
	return session, true
}

func (s *SessionStore) Delete(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
}
