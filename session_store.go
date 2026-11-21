package keycloakopenid

import (
	"container/list"
	"sync"
	"time"
)

// Session holds the tokens and validated identity of one authenticated browser
// session. Its mutex serializes token rotation so a refresh cannot interleave
// with another reader or writer of the same session.
type Session struct {
	mu               sync.Mutex
	AccessToken      string
	RefreshToken     string
	ExpiresAt        time.Time
	RefreshExpiresAt time.Time
	Subject          string
	Claims           map[string]any
}

func (s *Session) snapshot() (accessToken, refreshToken string, expiresAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.AccessToken, s.RefreshToken, s.ExpiresAt
}

// expiredLocked reports whether the session can neither authorize nor be
// renewed. The caller must hold the session lock. A session expires exactly at
// its expiry timestamp, matching the OIDC exp claim, which is valid only while
// now is strictly before exp.
func (s *Session) expiredLocked(now time.Time) bool {
	accessExpired := !s.ExpiresAt.IsZero() && !now.Before(s.ExpiresAt)
	if s.RefreshToken == "" {
		return accessExpired
	}
	return accessExpired && !s.RefreshExpiresAt.IsZero() && !now.Before(s.RefreshExpiresAt)
}

// applyTokenSet atomically replaces the session's tokens and expiry from a
// token set produced by an exchange or refresh.
func (s *Session) applyTokenSet(ts *tokenSet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applyTokenSetLocked(ts)
}

// applyTokenSetLocked applies a token set assuming the caller already holds the
// session lock. RefreshExpiresIn semantics: nil preserves the previous refresh
// expiry, 0 clears it (no fixed expiry), and a positive value replaces it. A
// negative value is invalid and is rejected before a token set is built, so it
// is never observed here. A non-empty identity subject replaces the stored
// identity; an empty subject preserves it.
func (s *Session) applyTokenSetLocked(ts *tokenSet) {
	s.AccessToken = ts.AccessToken
	if ts.RefreshToken != "" {
		s.RefreshToken = ts.RefreshToken
	}
	s.ExpiresAt = time.Now().Add(time.Duration(ts.ExpiresIn) * time.Second)

	switch {
	case ts.RefreshExpiresIn == nil:
		// preserve the previous refresh expiry
	case *ts.RefreshExpiresIn == 0:
		s.RefreshExpiresAt = time.Time{}
	case *ts.RefreshExpiresIn > 0:
		s.RefreshExpiresAt = time.Now().Add(time.Duration(*ts.RefreshExpiresIn) * time.Second)
	default:
		// negative is invalid; preserve to avoid corrupting state
	}

	if ts.Identity.Subject != "" {
		s.Subject = ts.Identity.Subject
		s.Claims = ts.Identity.Claims
	}
}

var (
	sharedStoresMu sync.Mutex
	sharedStores   = map[string]*SessionStore{}
)

// sessionCleanupInterval is how often each process-global store sweeps expired
// sessions in the background.
const sessionCleanupInterval = time.Minute

var (
	sharedLoginStoresMu sync.Mutex
	sharedLoginStores   = map[string]*loginStore{}
)

// sharedLoginStore returns the process-wide pending-login store for one
// Keycloak client, creating it with the fixed per-client capacity on first use.
// As with sessions, pending logins must survive middleware-instance recreation
// on configuration reload, so they are shared across instances.
func sharedLoginStore(key, callbackURI string) *loginStore {
	sharedLoginStoresMu.Lock()
	defer sharedLoginStoresMu.Unlock()
	store, ok := sharedLoginStores[key]
	if !ok {
		store = newLoginStore(callbackURI, loginCapacity)
		sharedLoginStores[key] = store
	}
	store.startCleanup()
	return store
}

// sharedSessionStore returns the process-wide store for one Keycloak client,
// creating it with the given capacity on first use. Traefik creates a
// middleware instance per router and recreates every instance on each
// configuration reload, so sessions must outlive instances. A single cleanup
// goroutine is started per store.
func sharedSessionStore(key string, capacity int) *SessionStore {
	sharedStoresMu.Lock()
	defer sharedStoresMu.Unlock()
	store, ok := sharedStores[key]
	if !ok {
		store = NewSessionStore(capacity)
		sharedStores[key] = store
	}
	store.startCleanup()
	return store
}

// sessionEntry links a stored session to its position in the LRU order.
type sessionEntry struct {
	id      string
	session *Session
	element *list.Element
}

// SessionStore is a capacity-bounded LRU cache of sessions keyed by session ID.
// The store lock guards the map and LRU order and is never held while waiting
// on a session lock, so a slow renewal cannot block unrelated request paths.
type SessionStore struct {
	mu        sync.Mutex
	capacity  int
	order     *list.List
	byID      map[string]*list.Element
	startOnce sync.Once
}

// NewSessionStore returns an empty store with the given capacity. A cleanup
// goroutine is started separately by sharedSessionStore, never here, so tests
// can exercise the store without leaving background goroutines behind.
func NewSessionStore(capacity int) *SessionStore {
	return &SessionStore{
		capacity: capacity,
		order:    list.New(),
		byID:     make(map[string]*list.Element),
	}
}

func (s *SessionStore) startCleanup() {
	s.startOnce.Do(func() {
		go s.cleanupLoop(sessionCleanupInterval)
	})
}

func (s *SessionStore) cleanupLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		s.Cleanup(time.Now())
	}
}

// SetCapacity adjusts the store's capacity and immediately evicts the least
// recently used sessions until the store is within the new bound.
func (s *SessionStore) SetCapacity(capacity int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.capacity = capacity
	s.trim()
}

// Set inserts or replaces the session for id and marks it most recently used.
// It is O(1): an insertion or update plus LRU eviction only. It never scans for
// expired sessions.
func (s *SessionStore) Set(id string, session *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if elem, ok := s.byID[id]; ok {
		elem.Value.(*sessionEntry).session = session
		s.order.MoveToFront(elem)
		return
	}
	entry := &sessionEntry{id: id, session: session}
	entry.element = s.order.PushFront(entry)
	s.byID[id] = entry.element
	s.trim()
}

// trim evicts the least recently used sessions until the store is within its
// capacity. The caller must hold the store lock.
func (s *SessionStore) trim() {
	for s.order.Len() > s.capacity {
		back := s.order.Back()
		if back == nil {
			return
		}
		entry := back.Value.(*sessionEntry)
		s.order.Remove(back)
		delete(s.byID, entry.id)
	}
}

// Get returns the session for id if it exists and has not expired, marking it
// most recently used. An expired session is deleted on access.
func (s *SessionStore) Get(id string) (*Session, bool) {
	s.mu.Lock()
	elem, ok := s.byID[id]
	if !ok {
		s.mu.Unlock()
		return nil, false
	}
	session := elem.Value.(*sessionEntry).session
	s.order.MoveToFront(elem)
	s.mu.Unlock()

	if s.removeExpired(id, session, time.Now()) {
		return nil, false
	}
	return session, true
}

// Delete removes the session for id if present.
func (s *SessionStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if elem, ok := s.byID[id]; ok {
		s.order.Remove(elem)
		delete(s.byID, id)
	}
}

// Cleanup deletes every session that has expired as of now. It never holds the
// store lock while waiting on a session lock, so a session blocked in renewal
// does not stall the sweep or any request path.
func (s *SessionStore) Cleanup(now time.Time) {
	s.mu.Lock()
	candidates := make([]*sessionEntry, 0, len(s.byID))
	for elem := s.order.Front(); elem != nil; elem = elem.Next() {
		candidates = append(candidates, elem.Value.(*sessionEntry))
	}
	s.mu.Unlock()

	for _, entry := range candidates {
		s.removeExpired(entry.id, entry.session, now)
	}
}

// removeExpired deletes id if the store still maps it to session and the
// session has expired as of now. It holds the session lock while rechecking
// expiry and, before deleting, verifies the store entry still points at the
// same session, so a concurrent renewal or replacement is never deleted. It
// reports whether the entry was removed.
func (s *SessionStore) removeExpired(id string, session *Session, now time.Time) bool {
	session.mu.Lock()
	defer session.mu.Unlock()
	if !session.expiredLocked(now) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if elem, ok := s.byID[id]; ok && elem.Value.(*sessionEntry).session == session {
		s.order.Remove(elem)
		delete(s.byID, id)
		return true
	}
	return false
}
