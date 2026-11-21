package keycloakopenid

import (
	"container/list"
	"context"
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
	Nonce            string
	Audience         []string
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
		if s.Subject == "" {
			s.Nonce = ts.Identity.Nonce
			s.Audience = append([]string(nil), ts.Identity.Audience...)
		}
		s.Subject = ts.Identity.Subject
		s.Claims = ts.Identity.Claims
	}
}

// sessionCleanupInterval is how often each store sweeps expired sessions in
// the background.
const sessionCleanupInterval = time.Minute

// sharedStoreRetirementGrace is how long an unreferenced client's stores are
// retained so a configuration reload can reacquire them without losing state.
const sharedStoreRetirementGrace = 5 * time.Minute

// sharedClientStores holds the stores shared by every middleware instance for
// one client.
type sharedClientStores struct {
	sessions *SessionStore
	logins   *loginStore
	refs     int
	retire   *time.Timer
}

var (
	sharedStoresMu sync.Mutex
	sharedStores   = map[string]*sharedClientStores{}
)

// acquireSharedStores returns the stores shared by one client, creating them on
// first use. Each acquisition is released when ctx is canceled, so a middleware
// instance's lifetime drives the store reference count.
func acquireSharedStores(ctx context.Context, key string, sessionCapacity int) (*SessionStore, *loginStore) {
	sharedStoresMu.Lock()
	entry, ok := sharedStores[key]
	if !ok {
		entry = &sharedClientStores{
			sessions: NewSessionStore(sessionCapacity),
			logins:   newLoginStore(loginCapacity),
		}
		sharedStores[key] = entry
	}
	if entry.retire != nil {
		entry.retire.Stop()
		entry.retire = nil
	}
	entry.refs++
	entry.sessions.SetCapacity(sessionCapacity)
	entry.sessions.startCleanup()
	entry.logins.startCleanup()
	sharedStoresMu.Unlock()

	context.AfterFunc(ctx, func() {
		releaseSharedStores(key, entry)
	})
	return entry.sessions, entry.logins
}

// releaseSharedStores drops one acquisition. The last release schedules
// retirement after the grace period; reacquisition during that period cancels
// it.
func releaseSharedStores(key string, entry *sharedClientStores) {
	sharedStoresMu.Lock()
	current, ok := sharedStores[key]
	if !ok || current != entry || entry.refs <= 0 {
		sharedStoresMu.Unlock()
		return
	}
	entry.refs--
	if entry.refs > 0 {
		sharedStoresMu.Unlock()
		return
	}
	if entry.retire == nil {
		entry.retire = time.AfterFunc(sharedStoreRetirementGrace, func() {
			retireSharedStores(key, entry)
		})
	}
	sharedStoresMu.Unlock()
}

// retireSharedStores removes and closes a client's stores when the registry
// still holds that exact entry and no references remain. The registry lock is
// released before the stores are purged.
func retireSharedStores(key string, entry *sharedClientStores) {
	sharedStoresMu.Lock()
	current, ok := sharedStores[key]
	if !ok || current != entry || entry.refs != 0 {
		sharedStoresMu.Unlock()
		return
	}
	if entry.retire != nil {
		entry.retire.Stop()
		entry.retire = nil
	}
	delete(sharedStores, key)
	sharedStoresMu.Unlock()

	entry.sessions.Close()
	entry.logins.Close()
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
	closeOnce sync.Once
	stop      chan struct{}
	closed    bool
}

// NewSessionStore returns an empty store with the given capacity. A cleanup
// goroutine is started separately by acquireSharedStores, never here, so tests
// can exercise the store without leaving background goroutines behind.
func NewSessionStore(capacity int) *SessionStore {
	return &SessionStore{
		capacity: capacity,
		order:    list.New(),
		byID:     make(map[string]*list.Element),
		stop:     make(chan struct{}),
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
	for {
		select {
		case <-ticker.C:
			s.Cleanup(time.Now())
		case <-s.stop:
			return
		}
	}
}

// Close marks the store closed and clears every entry. A closed store rejects
// reads and writes. Close is idempotent.
func (s *SessionStore) Close() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.order.Init()
		s.byID = make(map[string]*list.Element)
		s.mu.Unlock()
		close(s.stop)
	})
}

// SetCapacity adjusts the store's capacity and immediately evicts the least
// recently used sessions until the store is within the new bound.
func (s *SessionStore) SetCapacity(capacity int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.capacity = capacity
	s.trim()
}

// Set inserts or replaces the session for id and marks it most recently used.
// It is O(1): an insertion or update plus LRU eviction only. It never scans for
// expired sessions.
func (s *SessionStore) Set(id string, session *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
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
	if s.closed {
		s.mu.Unlock()
		return nil, false
	}
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
	if s.closed {
		return
	}
	if elem, ok := s.byID[id]; ok {
		s.order.Remove(elem)
		delete(s.byID, id)
	}
}

// sessionCandidate is an immutable snapshot of one stored session used by
// Cleanup after it releases the store lock.
type sessionCandidate struct {
	id      string
	session *Session
}

// Cleanup deletes every session that has expired as of now. It never holds the
// store lock while waiting on a session lock, so a session blocked in renewal
// does not stall the sweep or any request path.
func (s *SessionStore) Cleanup(now time.Time) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	candidates := make([]sessionCandidate, 0, len(s.byID))
	for elem := s.order.Front(); elem != nil; elem = elem.Next() {
		entry := elem.Value.(*sessionEntry)
		candidates = append(candidates, sessionCandidate{id: entry.id, session: entry.session})
	}
	s.mu.Unlock()

	for _, candidate := range candidates {
		s.removeExpired(candidate.id, candidate.session, now)
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
	if s.closed {
		return false
	}
	if elem, ok := s.byID[id]; ok && elem.Value.(*sessionEntry).session == session {
		s.order.Remove(elem)
		delete(s.byID, id)
		return true
	}
	return false
}
