package keycloakopenid

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTestLoginStore(t *testing.T) *loginStore {
	t.Helper()
	return newLoginStore("https://app.test/callback", 10)
}

func TestBeginUnique256BitValues(t *testing.T) {
	store := newTestLoginStore(t)
	seen := make(map[string]bool)
	for i := 0; i < 64; i++ {
		state, nonce, verifier, err := store.Begin("/x")
		if err != nil {
			t.Fatalf("Begin: %v", err)
		}
		if state == nonce || state == verifier || nonce == verifier {
			t.Fatalf("state/nonce/verifier must be distinct: %q %q %q", state, nonce, verifier)
		}
		for _, v := range []string{state, nonce} {
			raw, err := base64.RawURLEncoding.DecodeString(v)
			if err != nil || len(raw) != 32 {
				t.Fatalf("value %q must be 256-bit base64url", v)
			}
			if seen[v] {
				t.Fatalf("value %q was generated twice", v)
			}
			seen[v] = true
		}
		if len(verifier) < 43 || len(verifier) > 128 {
			t.Fatalf("verifier %q is not a valid PKCE verifier", verifier)
		}
		if seen[verifier] {
			t.Fatalf("verifier %q was generated twice", verifier)
		}
		seen[verifier] = true
	}
}

func TestBeginStoresTransaction(t *testing.T) {
	store := newTestLoginStore(t)
	state, nonce, verifier, err := store.Begin("/dashboard?tab=1")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	tx, ok := store.Consume(state)
	if !ok {
		t.Fatal("Consume must return the stored transaction")
	}
	if tx.nonce != nonce {
		t.Fatalf("tx.nonce = %q, want %q", tx.nonce, nonce)
	}
	if tx.verifier != verifier {
		t.Fatalf("tx.verifier = %q, want %q", tx.verifier, verifier)
	}
	if tx.returnTarget != "/dashboard?tab=1" {
		t.Fatalf("tx.returnTarget = %q, want /dashboard?tab=1", tx.returnTarget)
	}
	if tx.callbackURI != "https://app.test/callback" {
		t.Fatalf("tx.callbackURI = %q, want the fixed callback", tx.callbackURI)
	}
	remaining := time.Until(tx.expiresAt)
	if remaining < 9*time.Minute+50*time.Second || remaining > 10*time.Minute+time.Second {
		t.Fatalf("expiresAt is %v away, want about 10m", remaining)
	}
}

func TestConsumeIsSingleUse(t *testing.T) {
	store := newTestLoginStore(t)
	state, _, _, _ := store.Begin("/x")

	if _, ok := store.Consume(state); !ok {
		t.Fatal("first Consume must succeed")
	}
	if _, ok := store.Consume(state); ok {
		t.Fatal("second Consume of the same state must fail")
	}
}

func TestConsumeUnknownStateFails(t *testing.T) {
	store := newTestLoginStore(t)
	if _, ok := store.Consume("missing"); ok {
		t.Fatal("Consume of an unknown state must fail")
	}
}

func TestConsumeConcurrentReplayExactlyOnce(t *testing.T) {
	store := newTestLoginStore(t)
	state, _, _, _ := store.Begin("/x")

	const workers = 32
	var wins int32
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := store.Consume(state); ok {
				atomic.AddInt32(&wins, 1)
			}
		}()
	}
	wg.Wait()

	if wins != 1 {
		t.Fatalf("Consume succeeded %d times, want exactly 1", wins)
	}
}

func TestLoginStoreCapacityEviction(t *testing.T) {
	store := newLoginStore("https://app.test/callback", 3)
	states := make([]string, 0, 4)
	for i := 0; i < 4; i++ {
		s, _, _, err := store.Begin("/x")
		if err != nil {
			t.Fatal(err)
		}
		states = append(states, s)
	}

	if _, ok := store.Consume(states[0]); ok {
		t.Fatal("oldest transaction must be evicted beyond capacity")
	}
	for _, s := range states[1:] {
		if _, ok := store.Consume(s); !ok {
			t.Fatalf("transaction %q within capacity must remain", s)
		}
	}
}

func TestLoginStoreExpiry(t *testing.T) {
	store := newTestLoginStore(t)
	state, _, _, _ := store.Begin("/x")

	store.mu.Lock()
	store.byState[state].Value.(*loginEntry).tx.expiresAt = time.Now().Add(-time.Second)
	store.mu.Unlock()

	if _, ok := store.Consume(state); ok {
		t.Fatal("expired transaction must not be consumed")
	}
}

func TestLoginStoreCleanup(t *testing.T) {
	store := newTestLoginStore(t)
	expired, _, _, _ := store.Begin("/a")
	live, _, _, _ := store.Begin("/b")

	store.mu.Lock()
	store.byState[expired].Value.(*loginEntry).tx.expiresAt = time.Now().Add(-time.Minute)
	store.mu.Unlock()

	store.Cleanup(time.Now())

	store.mu.Lock()
	n := len(store.byState)
	store.mu.Unlock()
	if n != 1 {
		t.Fatalf("store holds %d transactions after cleanup, want 1", n)
	}
	if _, ok := store.Consume(expired); ok {
		t.Fatal("expired transaction must be removed by cleanup")
	}
	if _, ok := store.Consume(live); !ok {
		t.Fatal("unexpired transaction must survive cleanup")
	}
}

func TestLoginStoreMultipleTabs(t *testing.T) {
	store := newTestLoginStore(t)
	const key = "https://kc/r/c"

	s1, _, _, err := store.Begin("/tab1")
	if err != nil {
		t.Fatal(err)
	}
	s2, _, _, err := store.Begin("/tab2")
	if err != nil {
		t.Fatal(err)
	}

	if s1 == s2 {
		t.Fatal("tabs must receive distinct states")
	}
	if loginCookieName(key, s1) == loginCookieName(key, s2) {
		t.Fatal("tabs must receive distinct login cookies")
	}

	tx1, ok1 := store.Consume(s1)
	tx2, ok2 := store.Consume(s2)
	if !ok1 || !ok2 {
		t.Fatalf("both tabs must be consumable: %t %t", ok1, ok2)
	}
	if tx1.returnTarget != "/tab1" || tx2.returnTarget != "/tab2" {
		t.Fatalf("return targets = %q %q, want /tab1 /tab2", tx1.returnTarget, tx2.returnTarget)
	}
}

func TestSafeReturnTarget(t *testing.T) {
	cases := []struct {
		name string
		u    *url.URL
		want string
		ok   bool
	}{
		{"path", &url.URL{Path: "/dashboard"}, "/dashboard", true},
		{"path and query", &url.URL{Path: "/dashboard", RawQuery: "tab=1&x=2"}, "/dashboard?tab=1&x=2", true},
		{"root", &url.URL{Path: "/"}, "/", true},
		{"empty path", &url.URL{}, "/", true},
		{"absolute", &url.URL{Scheme: "https", Host: "evil.test", Path: "/x"}, "", false},
		{"protocol relative", &url.URL{Host: "evil.test", Path: "/x"}, "", false},
		{"backslash", &url.URL{Path: "/foo\\bar"}, "", false},
		{"control char", &url.URL{Path: "/foo\x00bar"}, "", false},
		{"newline in query", &url.URL{Path: "/x", RawQuery: "a=\n"}, "", false},
		{"relative path", &url.URL{Path: "foo"}, "", false},
		{"nil", nil, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := safeReturnTarget(tc.u)
			if tc.ok {
				if err != nil {
					t.Fatalf("safeReturnTarget returned error: %v", err)
				}
				if got != tc.want {
					t.Fatalf("safeReturnTarget = %q, want %q", got, tc.want)
				}
			} else if err == nil {
				t.Fatalf("safeReturnTarget = %q, want error", got)
			}
		})
	}
}

func TestSessionCookieName(t *testing.T) {
	a := sessionCookieName("client-a")
	b := sessionCookieName("client-a")
	c := sessionCookieName("client-b")
	if a != b {
		t.Fatal("session cookie name must be deterministic")
	}
	if a == c {
		t.Fatal("distinct clients must have distinct cookie names")
	}
	if !strings.HasPrefix(a, "__Host-") {
		t.Fatalf("session cookie name %q must be a __Host- cookie", a)
	}
}

func TestLoginCookieName(t *testing.T) {
	key := "https://kc/r/c"
	a := loginCookieName(key, "state-a")
	b := loginCookieName(key, "state-a")
	c := loginCookieName(key, "state-b")
	if a != b {
		t.Fatal("login cookie name must be deterministic")
	}
	if a == c {
		t.Fatal("distinct states must have distinct cookie names")
	}
	if !strings.HasPrefix(a, "__Host-") {
		t.Fatalf("login cookie name %q must be a __Host- cookie", a)
	}
}

func TestCookieAttributes(t *testing.T) {
	key := "https://kc/r/c"
	state := "state-value"
	sessionID := "session-value"

	login := loginCookie(key, state)
	session := sessionCookie(key, sessionID)

	for _, c := range []*http.Cookie{login, session} {
		if c.Path != "/" {
			t.Fatalf("cookie %q Path = %q, want /", c.Name, c.Path)
		}
		if !c.Secure {
			t.Fatalf("cookie %q must be Secure", c.Name)
		}
		if !c.HttpOnly {
			t.Fatalf("cookie %q must be HttpOnly", c.Name)
		}
		if c.SameSite != http.SameSiteLaxMode {
			t.Fatalf("cookie %q SameSite = %v, want Lax", c.Name, c.SameSite)
		}
		if c.Domain != "" {
			t.Fatalf("cookie %q must be host-only (no Domain)", c.Name)
		}
	}
	if login.Value != state {
		t.Fatalf("login cookie value = %q, want the state %q", login.Value, state)
	}
	if session.Value != sessionID {
		t.Fatalf("session cookie value = %q, want the session id", session.Value)
	}
}

func TestCookieClearMatchesIssuance(t *testing.T) {
	key := "https://kc/r/c"
	state := "state-value"
	sessionID := "session-value"

	pairs := []struct {
		issue *http.Cookie
		clear *http.Cookie
	}{
		{loginCookie(key, state), clearLoginCookie(key, state)},
		{sessionCookie(key, sessionID), clearSessionCookie(key)},
	}
	for _, p := range pairs {
		if p.issue.Name != p.clear.Name {
			t.Fatalf("clear name %q != issue name %q", p.clear.Name, p.issue.Name)
		}
		if p.issue.Path != p.clear.Path {
			t.Fatalf("clear Path %q != issue Path %q", p.clear.Path, p.issue.Path)
		}
		if p.issue.Domain != p.clear.Domain {
			t.Fatalf("clear Domain %q != issue Domain %q", p.clear.Domain, p.issue.Domain)
		}
		if p.clear.Secure != p.issue.Secure || p.clear.HttpOnly != p.issue.HttpOnly || p.clear.SameSite != p.issue.SameSite {
			t.Fatal("clear cookie must match issuance Secure/HttpOnly/SameSite")
		}
		if p.clear.MaxAge >= 0 {
			t.Fatal("clear cookie must expire immediately")
		}
	}
}

func resetSharedLoginStores() {
	sharedLoginStoresMu.Lock()
	defer sharedLoginStoresMu.Unlock()
	sharedLoginStores = map[string]*loginStore{}
}

func TestSharedLoginStore(t *testing.T) {
	resetSharedLoginStores()
	a := sharedLoginStore("client-a", "https://app.test/callback")
	b := sharedLoginStore("client-a", "https://app.test/callback")
	if a != b {
		t.Fatal("same client key must resolve to the same login store")
	}
	c := sharedLoginStore("client-b", "https://app.test/callback")
	if a == c {
		t.Fatal("distinct client keys must resolve to distinct login stores")
	}
	if a.capacity != loginCapacity {
		t.Fatalf("shared login store capacity = %d, want %d", a.capacity, loginCapacity)
	}
}
