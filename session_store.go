package keycloakopenid

import (
	"sync"
	"time"
)

type Session struct {
	mu           sync.Mutex
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

func (s *Session) snapshot() (accessToken, refreshToken string, expiresAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.AccessToken, s.RefreshToken, s.ExpiresAt
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
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sessionID] = session
}

func (s *SessionStore) Get(sessionID string) (*Session, bool) {
	s.mu.RLock()
	session, exists := s.sessions[sessionID]
	s.mu.RUnlock()
	if !exists {
		return nil, false
	}
	_, refreshToken, expiresAt := session.snapshot()
	if refreshToken == "" && !expiresAt.IsZero() && time.Now().After(expiresAt) {
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
