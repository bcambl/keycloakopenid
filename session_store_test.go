package keycloakopenid

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestSessionStoreSetGetDelete(t *testing.T) {
	store := NewSessionStore(10)
	session := &Session{AccessToken: "a"}
	store.Set("id", session)

	got, ok := store.Get("id")
	if !ok {
		t.Fatal("expected stored session to be found")
	}
	if got != session {
		t.Fatal("expected Get to return the stored session pointer")
	}

	store.Delete("id")
	if _, ok := store.Get("id"); ok {
		t.Fatal("expected miss after delete")
	}
}

func TestSessionStoreGetUpdatesRecency(t *testing.T) {
	store := NewSessionStore(2)
	store.Set("a", &Session{AccessToken: "a"})
	store.Set("b", &Session{AccessToken: "b"})

	// Accessing "a" makes "b" the least recently used.
	if _, ok := store.Get("a"); !ok {
		t.Fatal("expected a to be present")
	}
	store.Set("c", &Session{AccessToken: "c"})

	if _, ok := store.Get("b"); ok {
		t.Fatal("least recently used session must be evicted")
	}
	if _, ok := store.Get("a"); !ok {
		t.Fatal("recently accessed session must survive")
	}
	if _, ok := store.Get("c"); !ok {
		t.Fatal("new session must be present")
	}
}

func TestSessionStoreSetUpdatesExisting(t *testing.T) {
	store := NewSessionStore(2)
	old := &Session{AccessToken: "old"}
	store.Set("id", old)

	replacement := &Session{AccessToken: "new"}
	store.Set("id", replacement)

	got, ok := store.Get("id")
	if !ok {
		t.Fatal("expected updated session to be found")
	}
	if got != replacement {
		t.Fatal("Set must replace the session for an existing id")
	}

	store.mu.Lock()
	n := len(store.byID)
	store.mu.Unlock()
	if n != 1 {
		t.Fatalf("store holds %d entries, want 1 after update", n)
	}
}

func TestSessionStoreCapacityEvictsLeastRecentlyUsed(t *testing.T) {
	store := NewSessionStore(3)
	for _, id := range []string{"a", "b", "c", "d"} {
		store.Set(id, &Session{AccessToken: id})
	}

	if _, ok := store.Get("a"); ok {
		t.Fatal("oldest session must be evicted beyond capacity")
	}
	for _, id := range []string{"b", "c", "d"} {
		if _, ok := store.Get(id); !ok {
			t.Fatalf("session %q must remain within capacity", id)
		}
	}
}

func TestSessionStoreShrinkingCapacityEvicts(t *testing.T) {
	store := NewSessionStore(5)
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		store.Set(id, &Session{AccessToken: id})
	}

	store.SetCapacity(2)

	if _, ok := store.Get("a"); ok {
		t.Fatal("shrinking capacity must evict the least recently used session")
	}
	if _, ok := store.Get("b"); ok {
		t.Fatal("shrinking capacity must evict the second least recently used session")
	}
	if _, ok := store.Get("c"); ok {
		t.Fatal("shrinking capacity must evict the third least recently used session")
	}
	for _, id := range []string{"d", "e"} {
		if _, ok := store.Get(id); !ok {
			t.Fatalf("session %q must remain after shrinking", id)
		}
	}
}

func TestSessionStoreSetDoesNotScanExpiry(t *testing.T) {
	store := NewSessionStore(10)
	past := time.Now().Add(-time.Minute)
	store.Set("expired", &Session{AccessToken: "a", ExpiresAt: past})

	// A new Set must not trigger a sweep of expired sessions.
	store.Set("other", &Session{AccessToken: "b"})

	if _, ok := store.Get("expired"); ok {
		t.Fatal("expired session must still be evicted on access")
	}

	// Re-insert and confirm Set alone leaves expired sessions in place.
	store.Set("expired", &Session{AccessToken: "a", ExpiresAt: past})
	store.Set("other", &Session{AccessToken: "c"})
	store.mu.Lock()
	n := len(store.byID)
	store.mu.Unlock()
	if n != 2 {
		t.Fatalf("store holds %d entries after Set, want 2; Set must not scan for expiry", n)
	}
}

func TestSessionStoreLazyExpiry(t *testing.T) {
	store := NewSessionStore(10)
	store.Set("past", &Session{AccessToken: "a", ExpiresAt: time.Now().Add(-time.Minute)})
	if _, ok := store.Get("past"); ok {
		t.Fatal("expired session must miss")
	}
	if _, ok := store.Get("past"); ok {
		t.Fatal("expired session must stay deleted")
	}

	store.Set("future", &Session{AccessToken: "b", ExpiresAt: time.Now().Add(time.Hour)})
	if _, ok := store.Get("future"); !ok {
		t.Fatal("unexpired session must hit")
	}
}

func TestSessionStoreZeroExpiryNeverExpires(t *testing.T) {
	store := NewSessionStore(10)
	store.Set("none", &Session{AccessToken: "c"})
	if _, ok := store.Get("none"); !ok {
		t.Fatal("session with zero ExpiresAt must not expire")
	}
}

func TestSessionStoreRenewableSessionExpiresWithRefreshToken(t *testing.T) {
	store := NewSessionStore(10)
	store.Set("dead", &Session{AccessToken: "old", RefreshToken: "rt", ExpiresAt: time.Now().Add(-time.Minute), RefreshExpiresAt: time.Now().Add(-time.Second)})
	if _, ok := store.Get("dead"); ok {
		t.Fatal("session whose access and refresh tokens have both expired must miss")
	}
}

func TestSessionStoreRenewableSessionSurvivesWhileAccessTokenActive(t *testing.T) {
	store := NewSessionStore(10)
	store.Set("live", &Session{AccessToken: "a", RefreshToken: "rt", ExpiresAt: time.Now().Add(time.Minute), RefreshExpiresAt: time.Now().Add(-time.Second)})
	if _, ok := store.Get("live"); !ok {
		t.Fatal("session with an unexpired access token must hit even when its refresh token expired")
	}
}

func TestSessionStoreRenewableSessionSurvivesAccessTokenExpiry(t *testing.T) {
	store := NewSessionStore(10)
	store.Set("renewable", &Session{AccessToken: "old", RefreshToken: "rt", ExpiresAt: time.Now().Add(-time.Minute)})
	if _, ok := store.Get("renewable"); !ok {
		t.Fatal("renewable session must not be expired by access-token expiry")
	}
}

func TestSessionStoreCleanupRemovesExpired(t *testing.T) {
	store := NewSessionStore(10)
	now := time.Now()
	store.Set("old", &Session{AccessToken: "a", ExpiresAt: now.Add(-time.Hour)})
	store.Set("middle", &Session{AccessToken: "b", ExpiresAt: now.Add(time.Minute)})
	store.Set("later", &Session{AccessToken: "c", ExpiresAt: now.Add(time.Hour)})

	store.Cleanup(now)

	if _, ok := store.Get("old"); ok {
		t.Fatal("session expired before the cleanup time must be removed")
	}
	if _, ok := store.Get("middle"); !ok {
		t.Fatal("session expiring after the cleanup time must survive")
	}
	if _, ok := store.Get("later"); !ok {
		t.Fatal("session expiring much later must survive")
	}
}

func TestSessionStorePeriodicCleanupSteps(t *testing.T) {
	store := NewSessionStore(10)
	base := time.Now()
	store.Set("first", &Session{AccessToken: "a", ExpiresAt: base.Add(time.Minute)})
	store.Set("second", &Session{AccessToken: "b", ExpiresAt: base.Add(2 * time.Minute)})
	store.Set("offline", &Session{AccessToken: "o", RefreshToken: "rt"})

	store.Cleanup(base.Add(90 * time.Second))
	if _, ok := store.Get("first"); ok {
		t.Fatal("first session must be removed by the first sweep")
	}
	if _, ok := store.Get("second"); !ok {
		t.Fatal("second session must survive the first sweep")
	}

	store.Cleanup(base.Add(3 * time.Minute))
	if _, ok := store.Get("second"); ok {
		t.Fatal("second session must be removed by the second sweep")
	}
}

func TestSessionStoreOfflineSessionsSurviveCleanup(t *testing.T) {
	store := NewSessionStore(10)
	store.Set("offline", &Session{AccessToken: "a", RefreshToken: "rt", ExpiresAt: time.Now().Add(-time.Hour)})
	store.Cleanup(time.Now())
	if _, ok := store.Get("offline"); !ok {
		t.Fatal("session with no fixed refresh expiry must survive time cleanup")
	}
}

func TestSessionStoreExactExpiry(t *testing.T) {
	store := NewSessionStore(10)
	now := time.Now()
	store.Set("exact", &Session{AccessToken: "a", ExpiresAt: now})
	store.Set("future", &Session{AccessToken: "b", ExpiresAt: now.Add(time.Second)})

	store.Cleanup(now)

	if _, ok := store.Get("exact"); ok {
		t.Fatal("session at its exact expiry time must be expired")
	}
	if _, ok := store.Get("future"); !ok {
		t.Fatal("session expiring after the cleanup time must survive")
	}
}

func TestSessionStoreCleanupRechecksExpiryUnderLock(t *testing.T) {
	store := NewSessionStore(10)
	s := &Session{AccessToken: "a", RefreshToken: "rt", ExpiresAt: time.Now().Add(-time.Minute)}
	store.Set("id", s)

	// Simulate an in-flight renewal holding the session lock while the cleanup
	// goroutine runs. Renewal extends the expiry before releasing the lock.
	s.mu.Lock()
	cleanupDone := make(chan struct{})
	go func() {
		store.Cleanup(time.Now())
		close(cleanupDone)
	}()
	time.Sleep(10 * time.Millisecond)
	s.ExpiresAt = time.Now().Add(time.Hour)
	s.RefreshExpiresAt = time.Time{}
	s.mu.Unlock()
	<-cleanupDone

	if _, ok := store.Get("id"); !ok {
		t.Fatal("session renewed while cleanup was blocked must survive")
	}
}

func TestSessionStoreCleanupConcurrentReplacement(t *testing.T) {
	store := NewSessionStore(10)
	const iterations = 1000
	for i := 0; i < iterations; i++ {
		old := &Session{AccessToken: "old", ExpiresAt: time.Now().Add(-time.Minute)}
		replacement := &Session{AccessToken: "new", ExpiresAt: time.Now().Add(time.Hour)}
		store.Set("id", old)

		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			store.Cleanup(time.Now())
		}()
		go func() {
			defer wg.Done()
			<-start
			store.Set("id", replacement)
		}()
		close(start)
		wg.Wait()

		got, ok := store.Get("id")
		if !ok {
			t.Fatalf("iteration %d: replacement session was deleted", i)
		}
		if got != replacement {
			t.Fatalf("iteration %d: retained session = %p, want replacement %p", i, got, replacement)
		}
	}
}

func TestSessionStoreCleanupVerifyIdentity(t *testing.T) {
	store := NewSessionStore(10)
	old := &Session{AccessToken: "old", ExpiresAt: time.Now().Add(-time.Minute)}
	store.Set("id", old)

	fresh := &Session{AccessToken: "fresh", ExpiresAt: time.Now().Add(time.Hour)}
	store.Set("id", fresh)

	// A stale cleanup still holding the old pointer must not delete the
	// replacement.
	if store.removeExpired("id", old, time.Now()) {
		t.Fatal("must not delete a session that has been replaced")
	}
	if got, ok := store.Get("id"); !ok || got.AccessToken != "fresh" {
		t.Fatal("replacement session must remain in the store")
	}
}

func TestSessionStoreEvictedSessionNotResurrected(t *testing.T) {
	store := NewSessionStore(1)
	s := &Session{AccessToken: "old", RefreshToken: "rt1", ExpiresAt: time.Now().Add(-time.Second)}
	store.Set("a", s)

	locked := make(chan struct{})
	proceed := make(chan struct{})
	refreshed := make(chan struct{})
	go func() {
		defer close(refreshed)
		s.mu.Lock()
		close(locked)
		<-proceed
		s.AccessToken = "new"
		s.RefreshToken = "rt2"
		s.ExpiresAt = time.Now().Add(time.Hour)
		s.mu.Unlock()
	}()

	<-locked
	store.Set("b", &Session{AccessToken: "b-token"})
	close(proceed)
	<-refreshed

	if _, ok := store.Get("a"); ok {
		t.Fatal("a session evicted mid-refresh must not be resurrected")
	}
	if got, ok := store.Get("b"); !ok || got.AccessToken != "b-token" {
		t.Fatalf("new session missing: %+v, ok=%t", got, ok)
	}
}

func TestSessionApplyTokenSetRotatesTokens(t *testing.T) {
	s := &Session{AccessToken: "old", RefreshToken: "rt1", ExpiresAt: time.Now().Add(-time.Second)}
	s.applyTokenSet(&tokenSet{AccessToken: "new", RefreshToken: "rt2", ExpiresIn: 300})

	if s.AccessToken != "new" {
		t.Fatalf("AccessToken = %q, want new", s.AccessToken)
	}
	if s.RefreshToken != "rt2" {
		t.Fatalf("RefreshToken = %q, want rt2", s.RefreshToken)
	}
	remaining := time.Until(s.ExpiresAt)
	if remaining < 295*time.Second || remaining > 305*time.Second {
		t.Fatalf("ExpiresAt is %v away, want about 300s", remaining)
	}
}

func TestSessionApplyTokenSetPreservesRefreshTokenWhenEmpty(t *testing.T) {
	s := &Session{AccessToken: "old", RefreshToken: "rt1", ExpiresAt: time.Now().Add(-time.Second)}
	s.applyTokenSet(&tokenSet{AccessToken: "new", ExpiresIn: 300})
	if s.RefreshToken != "rt1" {
		t.Fatalf("RefreshToken = %q, want rt1 retained when response omits refresh_token", s.RefreshToken)
	}
}

func TestSessionApplyTokenSetRefreshExpirySemantics(t *testing.T) {
	t.Run("nil preserves", func(t *testing.T) {
		s := &Session{AccessToken: "old", RefreshToken: "rt", ExpiresAt: time.Now(), RefreshExpiresAt: time.Now().Add(time.Hour)}
		s.applyTokenSet(&tokenSet{AccessToken: "new", RefreshToken: "rt", ExpiresIn: 300, RefreshExpiresIn: nil})
		if s.RefreshExpiresAt.IsZero() {
			t.Fatal("nil RefreshExpiresIn must preserve the previous refresh expiry")
		}
	})

	t.Run("zero clears", func(t *testing.T) {
		s := &Session{AccessToken: "old", RefreshToken: "rt", ExpiresAt: time.Now(), RefreshExpiresAt: time.Now().Add(time.Hour)}
		s.applyTokenSet(&tokenSet{AccessToken: "new", RefreshToken: "rt", ExpiresIn: 300, RefreshExpiresIn: intPtr(0)})
		if !s.RefreshExpiresAt.IsZero() {
			t.Fatal("zero RefreshExpiresIn must clear the refresh expiry")
		}
	})

	t.Run("positive replaces", func(t *testing.T) {
		s := &Session{AccessToken: "old", RefreshToken: "rt", ExpiresAt: time.Now()}
		s.applyTokenSet(&tokenSet{AccessToken: "new", RefreshToken: "rt", ExpiresIn: 300, RefreshExpiresIn: intPtr(1800)})
		remaining := time.Until(s.RefreshExpiresAt)
		if remaining < 1795*time.Second || remaining > 1805*time.Second {
			t.Fatalf("RefreshExpiresAt is %v away, want about 1800s", remaining)
		}
	})

	t.Run("negative invalid preserves", func(t *testing.T) {
		s := &Session{AccessToken: "old", RefreshToken: "rt", ExpiresAt: time.Now(), RefreshExpiresAt: time.Now().Add(time.Hour)}
		s.applyTokenSet(&tokenSet{AccessToken: "new", RefreshToken: "rt", ExpiresIn: 300, RefreshExpiresIn: intPtr(-1)})
		if s.RefreshExpiresAt.IsZero() || time.Until(s.RefreshExpiresAt) <= 0 {
			t.Fatal("negative RefreshExpiresIn is invalid and must not corrupt the refresh expiry")
		}
	})
}

func TestSessionApplyTokenSetIdentity(t *testing.T) {
	t.Run("nonempty subject replaces", func(t *testing.T) {
		s := &Session{AccessToken: "old", Subject: "previous"}
		s.applyTokenSet(&tokenSet{AccessToken: "new", ExpiresIn: 300, Identity: identity{Subject: "alice", Claims: map[string]any{"preferred_username": "alice"}}})
		if s.Subject != "alice" {
			t.Fatalf("Subject = %q, want alice", s.Subject)
		}
		if s.Claims["preferred_username"] != "alice" {
			t.Fatalf("Claims = %v, want preferred_username alice", s.Claims)
		}
	})

	t.Run("empty subject preserves", func(t *testing.T) {
		s := &Session{AccessToken: "old", Subject: "previous", Claims: map[string]any{"x": "y"}}
		s.applyTokenSet(&tokenSet{AccessToken: "new", ExpiresIn: 300})
		if s.Subject != "previous" {
			t.Fatalf("Subject = %q, want previous preserved", s.Subject)
		}
		if s.Claims["x"] != "y" {
			t.Fatal("Claims must be preserved when the token set carries no identity")
		}
	})
}

func TestSharedStoresSameKey(t *testing.T) {
	resetSharedStores()
	sessionsA, loginsA := acquireSharedStores(context.Background(), "client-a", 5)
	sessionsB, loginsB := acquireSharedStores(context.Background(), "client-a", 7)
	if sessionsA != sessionsB {
		t.Fatal("same client key must resolve to the same session store")
	}
	if loginsA != loginsB {
		t.Fatal("same client key must resolve to the same login store")
	}
}

func TestSharedStoresDistinctKeys(t *testing.T) {
	resetSharedStores()
	a, _ := acquireSharedStores(context.Background(), "client-a", 5)
	b, _ := acquireSharedStores(context.Background(), "client-b", 5)
	if a == b {
		t.Fatal("distinct client keys must resolve to distinct stores")
	}
	a.Set("id", &Session{AccessToken: "a"})
	if _, ok := b.Get("id"); ok {
		t.Fatal("stores for distinct clients must be isolated")
	}
}

func waitForSharedRefs(t *testing.T, key string, want int) *sharedClientStores {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		sharedStoresMu.Lock()
		entry := sharedStores[key]
		refs := -1
		if entry != nil {
			refs = entry.refs
		}
		sharedStoresMu.Unlock()
		if refs == want {
			return entry
		}
		if time.Now().After(deadline) {
			t.Fatalf("shared store %q reached %d references, want %d", key, refs, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestSharedStoresReloadDuringGrace(t *testing.T) {
	resetSharedStores()
	key := "client-a"
	ctx, cancel := context.WithCancel(context.Background())
	sessions, logins := acquireSharedStores(ctx, key, 10)
	sessions.Set("session", &Session{AccessToken: "a"})
	cancel()

	entry := waitForSharedRefs(t, key, 0)
	if entry.retire == nil {
		t.Fatal("zero references must schedule retirement")
	}

	reloadedSessions, reloadedLogins := acquireSharedStores(context.Background(), key, 10)
	if reloadedSessions != sessions || reloadedLogins != logins {
		t.Fatal("reacquisition during the grace period must preserve the existing stores")
	}
	if entry.retire != nil {
		t.Fatal("reacquisition must cancel the scheduled retirement")
	}
	if _, ok := reloadedSessions.Get("session"); !ok {
		t.Fatal("reacquisition must retain stored sessions")
	}

	retireSharedStores(key, entry)
	if _, ok := reloadedSessions.Get("session"); !ok {
		t.Fatal("a stopped retirement callback must not purge a reacquired store")
	}
}

func TestSharedStoresRetireAfterLastContext(t *testing.T) {
	resetSharedStores()
	key := "client-a"
	firstCtx, cancelFirst := context.WithCancel(context.Background())
	firstSessions, firstLogins := acquireSharedStores(firstCtx, key, 10)
	firstSessions.Set("session", &Session{AccessToken: "a"})

	secondCtx, cancelSecond := context.WithCancel(context.Background())
	secondSessions, secondLogins := acquireSharedStores(secondCtx, key, 10)
	if secondSessions != firstSessions || secondLogins != firstLogins {
		t.Fatal("independent acquisitions must share the same stores")
	}

	cancelFirst()
	waitForSharedRefs(t, key, 1)
	if _, ok := secondSessions.Get("session"); !ok {
		t.Fatal("canceling one context must not purge state while another reference remains")
	}

	cancelSecond()
	entry := waitForSharedRefs(t, key, 0)
	retireSharedStores(key, entry)

	sharedStoresMu.Lock()
	_, present := sharedStores[key]
	sharedStoresMu.Unlock()
	if present {
		t.Fatal("retirement must remove the registry entry")
	}
	if _, ok := secondSessions.Get("session"); ok {
		t.Fatal("retirement must clear stored sessions")
	}
	if _, _, _, err := secondLogins.Begin("/x"); err == nil {
		t.Fatal("retirement must reject new login transactions")
	}
}

func TestSharedStoresReacquireTimerRace(t *testing.T) {
	for i := 0; i < 100; i++ {
		resetSharedStores()
		key := "client-a"
		ctx, cancel := context.WithCancel(context.Background())
		sessions, _ := acquireSharedStores(ctx, key, 10)
		sessions.Set("session", &Session{AccessToken: "a"})
		cancel()
		entry := waitForSharedRefs(t, key, 0)

		start := make(chan struct{})
		var wg sync.WaitGroup
		var reacquired *SessionStore
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			retireSharedStores(key, entry)
		}()
		go func() {
			defer wg.Done()
			<-start
			reacquired, _ = acquireSharedStores(context.Background(), key, 10)
		}()
		close(start)
		wg.Wait()

		sharedStoresMu.Lock()
		current := sharedStores[key]
		sharedStoresMu.Unlock()
		if current == nil || current.sessions != reacquired {
			t.Fatalf("iteration %d: registry does not hold the reacquired entry", i)
		}
		if reacquired == sessions {
			if _, ok := reacquired.Get("session"); !ok {
				t.Fatalf("iteration %d: a reacquired store lost its sessions", i)
			}
		}
	}
}

func TestClosedStoresRejectReadsAndWrites(t *testing.T) {
	sessions := NewSessionStore(10)
	sessions.Set("id", &Session{AccessToken: "a"})
	sessions.Close()
	if _, ok := sessions.Get("id"); ok {
		t.Fatal("closed session store must miss reads")
	}
	sessions.Set("new", &Session{AccessToken: "b"})
	if _, ok := sessions.Get("new"); ok {
		t.Fatal("closed session store must reject writes")
	}
	sessions.Close()

	logins := newLoginStore(10)
	state, _, _, err := logins.Begin("/x")
	if err != nil {
		t.Fatalf("Begin returned error: %v", err)
	}
	logins.Close()
	if _, ok := logins.Consume(state); ok {
		t.Fatal("closed login store must reject Consume")
	}
	if _, _, _, err := logins.Begin("/x"); err == nil {
		t.Fatal("closed login store must reject Begin")
	}
	logins.Close()
}

func TestSessionStoreCleanupGoroutine(t *testing.T) {
	store := NewSessionStore(10)
	go store.cleanupLoop(5 * time.Millisecond)
	store.Set("expired", &Session{AccessToken: "a", ExpiresAt: time.Now().Add(-time.Hour)})

	deadline := time.Now().Add(time.Second)
	for {
		store.mu.Lock()
		n := len(store.byID)
		store.mu.Unlock()
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("cleanup goroutine did not remove the expired session")
		}
		time.Sleep(time.Millisecond)
	}
}
