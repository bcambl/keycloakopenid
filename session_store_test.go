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

func TestSessionStoreRenewableSessionSurvivesAccessTokenExpiry(t *testing.T) {
	store := NewSessionStore()
	store.Set("renewable", &Session{AccessToken: "old", RefreshToken: "rt", ExpiresAt: time.Now().Add(-time.Minute)})
	if _, ok := store.Get("renewable"); !ok {
		t.Fatal("renewable session must not be expired by access-token expiry")
	}
}
