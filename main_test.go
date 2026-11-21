package keycloakopenid

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// newAuth builds a middleware for the given OIDC test provider, applying
// mutate to the configuration before construction.
func newAuth(t *testing.T, p *oidcTestProvider, mutate func(*Config)) *keycloakAuth {
	t.Helper()
	config := Config{
		KeycloakURL:     p.srv.URL,
		ClientID:        p.clientID,
		ClientSecret:    "client-secret",
		KeycloakRealm:   "r",
		CallbackURL:     "https://app.test/callback",
		SessionCapacity: 10000,
	}
	if mutate != nil {
		mutate(&config)
	}
	handler, err := New(context.Background(), http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}), &config, "test")
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	auth, ok := handler.(*keycloakAuth)
	if !ok {
		t.Fatalf("handler is %T, want *keycloakAuth", handler)
	}
	return auth
}

// capture records what the next handler received.
type capture struct {
	called bool
	user   string
	authz  string
}

func (c *capture) handler() http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		c.called = true
		c.user = req.Header.Get("X-Forwarded-User")
		c.authz = req.Header.Get("Authorization")
		rw.WriteHeader(http.StatusOK)
	}
}

func navigationGet(target string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Accept", "text/html")
	return req
}

func apiGet(target string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("Accept", "application/json")
	return req
}

// peekLogin returns the nonce and verifier of a pending login transaction
// without consuming it.
func peekLogin(t *testing.T, auth *keycloakAuth, state string) (nonce, verifier string) {
	t.Helper()
	auth.loginStore.mu.Lock()
	defer auth.loginStore.mu.Unlock()
	elem := auth.loginStore.byState[state]
	if elem == nil {
		t.Fatalf("no pending transaction for state %q", state)
	}
	tx := elem.Value.(*loginEntry).tx
	return tx.nonce, tx.verifier
}

// validTokenResponse builds a token response with a signed ID token carrying
// the given nonce and the preferred_username "alice".
func validTokenResponse(p *oidcTestProvider, nonce, access string) string {
	claims := p.baseClaims()
	claims["nonce"] = nonce
	claims["at_hash"] = computeAtHash(access)
	claims["preferred_username"] = "alice"
	return marshalTokenResponse(access, "refresh-token", p.signIDToken(claims), 300, nil)
}

// startLogin drives a navigation request through the middleware and returns the
// callback state from the resulting auth redirect.
func startLogin(t *testing.T, auth *keycloakAuth, returnTarget string) string {
	t.Helper()
	rw := httptest.NewRecorder()
	auth.ServeHTTP(rw, navigationGet("https://app.test"+returnTarget))
	if rw.Code != http.StatusSeeOther {
		t.Fatalf("login start status = %d, want 303", rw.Code)
	}
	loc, err := url.Parse(rw.Header().Get("Location"))
	if err != nil {
		t.Fatalf("unparseable Location %q: %v", rw.Header().Get("Location"), err)
	}
	state := loc.Query().Get("state")
	if state == "" {
		t.Fatal("auth URL missing state")
	}
	return state
}

// completeLogin runs a full navigation login through the callback and returns
// the issued session cookie value plus the recorded authorization headers.
func completeLogin(t *testing.T, auth *keycloakAuth, p *oidcTestProvider, returnTarget string) string {
	t.Helper()
	state := startLogin(t, auth, returnTarget)
	nonce, verifier := peekLogin(t, auth, state)
	if verifier == "" {
		t.Fatal("login transaction missing verifier")
	}

	p.setToken(validTokenResponse(p, nonce, "access-token"))
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app.test/callback?code=CODE&state="+state, nil)
	req.AddCookie(&http.Cookie{Name: loginCookieName(auth.clientKey, state), Value: state})
	auth.ServeHTTP(rw, req)

	if rw.Code != http.StatusSeeOther {
		t.Fatalf("callback status = %d, want 303", rw.Code)
	}
	if loc := rw.Header().Get("Location"); loc != "https://app.test"+returnTarget {
		t.Fatalf("Location = %q, want %q", loc, "https://app.test"+returnTarget)
	}
	for _, c := range rw.Result().Cookies() {
		if c.Name == sessionCookieName(auth.clientKey) {
			return c.Value
		}
	}
	t.Fatal("no session cookie issued")
	return ""
}

func resetSharedStores() {
	sharedStoresMu.Lock()
	defer sharedStoresMu.Unlock()
	sharedStores = map[string]*SessionStore{}
}

func TestPKCEChallenge(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if got := pkceChallenge(verifier); got != want {
		t.Fatalf("pkceChallenge = %q, want %q", got, want)
	}
}

func TestResolveReturnTarget(t *testing.T) {
	cb, _ := url.Parse("https://app.test/callback")
	cases := []struct{ target, want string }{
		{"/dashboard", "https://app.test/dashboard"},
		{"/dashboard?tab=1", "https://app.test/dashboard?tab=1"},
		{"/foo%3Fbar", "https://app.test/foo%3Fbar"},
		{"/foo%3fbar?next=%2F", "https://app.test/foo%3fbar?next=%2F"},
		{"/", "https://app.test/"},
	}
	for _, tc := range cases {
		if got := resolveReturnTarget(cb, tc.target); got != tc.want {
			t.Fatalf("resolveReturnTarget(%q) = %q, want %q", tc.target, got, tc.want)
		}
	}
}

func TestIgnoredPathSegmentMatching(t *testing.T) {
	k := &keycloakAuth{IgnorePathPrefixes: []string{"/api", "/favicon.ico"}}
	cases := []struct {
		path string
		want bool
	}{
		{"/api", true},
		{"/api/users", true},
		{"/api/", true},
		{"/apix", false},
		{"/x/api", false},
		{"/favicon.ico", true},
		{"/favicon.ico.png", false},
		{"/healthz", false},
	}
	for _, tc := range cases {
		if got := k.isIgnoredPath(tc.path); got != tc.want {
			t.Fatalf("isIgnoredPath(%q) = %t, want %t", tc.path, got, tc.want)
		}
	}
}

func TestIsNavigationRequestTable(t *testing.T) {
	cases := []struct {
		name      string
		method    string
		fetchMode string
		accept    string
		xhr       bool
		want      bool
	}{
		{"navigation", http.MethodGet, "navigate", "text/html", false, true},
		{"cors", http.MethodGet, "cors", "application/json", false, false},
		{"no fetch metadata html", http.MethodGet, "", "text/html", false, true},
		{"no fetch metadata xhr", http.MethodGet, "", "text/html", true, false},
		{"post navigation", http.MethodPost, "navigate", "text/html", false, false},
		{"json accept", http.MethodGet, "", "application/json", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "https://app.test/x", nil)
			if tc.fetchMode != "" {
				req.Header.Set("Sec-Fetch-Mode", tc.fetchMode)
			}
			req.Header.Set("Accept", tc.accept)
			if tc.xhr {
				req.Header.Set("X-Requested-With", "XMLHttpRequest")
			}
			if got := isNavigationRequest(req); got != tc.want {
				t.Fatalf("isNavigationRequest = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestSessionCookieNameHasHostPrefix(t *testing.T) {
	name := sessionCookieName("https://kc/r/c")
	if !strings.HasPrefix(name, "__Host-") {
		t.Fatalf("session cookie name %q must carry the __Host- prefix", name)
	}
}
