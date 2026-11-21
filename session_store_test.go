package keycloakopenid

import (
	"testing"
	"time"
)

func TestSessionStoreSetGetDelete(t *testing.T) {
	store := NewSessionStore()
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

func TestSessionStoreLazyExpiry(t *testing.T) {
	store := NewSessionStore()
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
	store := NewSessionStore()
	store.Set("none", &Session{AccessToken: "c"})
	if _, ok := store.Get("none"); !ok {
		t.Fatal("session with zero ExpiresAt must not expire")
	}
}

func TestSessionStoreRenewableSessionExpiresWithRefreshToken(t *testing.T) {
	store := NewSessionStore()
	store.Set("dead", &Session{AccessToken: "old", RefreshToken: "rt", ExpiresAt: time.Now().Add(-time.Minute), RefreshExpiresAt: time.Now().Add(-time.Second)})
	if _, ok := store.Get("dead"); ok {
		t.Fatal("session whose access and refresh tokens have both expired must miss")
	}
}

func TestSessionStoreRenewableSessionSurvivesWhileAccessTokenActive(t *testing.T) {
	store := NewSessionStore()
	store.Set("live", &Session{AccessToken: "a", RefreshToken: "rt", ExpiresAt: time.Now().Add(time.Minute), RefreshExpiresAt: time.Now().Add(-time.Second)})
	if _, ok := store.Get("live"); !ok {
		t.Fatal("session with an unexpired access token must hit even when its refresh token expired")
	}
}

func TestSessionStoreSetEvictsUnusableSessions(t *testing.T) {
	store := NewSessionStore()
	past := time.Now().Add(-time.Minute)
	store.Set("legacy-expired", &Session{AccessToken: "a", ExpiresAt: past})
	store.Set("renewable-expired", &Session{AccessToken: "b", RefreshToken: "rt", ExpiresAt: past, RefreshExpiresAt: past})
	store.Set("renewable-live", &Session{AccessToken: "c", RefreshToken: "rt", ExpiresAt: past, RefreshExpiresAt: time.Now().Add(time.Hour)})

	store.Set("new", &Session{AccessToken: "d"})

	if got := len(store.sessions); got != 2 {
		t.Fatalf("stored sessions = %d, want 2 (unusable sessions that are never requested again must not accumulate)", got)
	}
	if _, ok := store.Get("renewable-live"); !ok {
		t.Fatal("renewable session with a valid refresh token must survive eviction")
	}
}

func TestSessionStoreRenewableSessionSurvivesAccessTokenExpiry(t *testing.T) {
	store := NewSessionStore()
	store.Set("renewable", &Session{AccessToken: "old", RefreshToken: "rt", ExpiresAt: time.Now().Add(-time.Minute)})
	if _, ok := store.Get("renewable"); !ok {
		t.Fatal("renewable session must not be expired by access-token expiry")
	}
}
