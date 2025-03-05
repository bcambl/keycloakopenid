package keycloakopenid

import (
	"sync"
	"time"
)

type SessionStore struct {
	sessions map[string]string
	mu       sync.RWMutex
}

func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]string),
	}
}

func (s *SessionStore) Set(sessionID, token string, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sessionID] = token
	go s.expire(sessionID, ttl)
}

func (s *SessionStore) Get(sessionID string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	token, exists := s.sessions[sessionID]
	return token, exists
}

func (s *SessionStore) expire(sessionID string, ttl time.Duration) {
	time.Sleep(ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
}
