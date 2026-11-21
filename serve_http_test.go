package keycloakopenid

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestCallbackStoresSessionAndRedirects drives a full login and checks the
// session is stored, the cookie is host-only, and the redirect is 303 to the
// return target against the callback origin.
func TestCallbackStoresSessionAndRedirects(t *testing.T) {
	p := newOIDCTestProvider(t)
	auth := newAuth(t, p, nil)

	sessionID := completeLogin(t, auth, p, "/dashboard?tab=1")

	session, ok := auth.SessionStore.Get(sessionID)
	if !ok {
		t.Fatal("expected stored session after callback")
	}
	if session.AccessToken != "access-token" {
		t.Fatalf("AccessToken = %q, want access-token", session.AccessToken)
	}
	if session.Subject != "user-123" {
		t.Fatalf("Subject = %q, want user-123", session.Subject)
	}
}

// TestCallbackRequiresGET rejects a non-GET request to the callback path.
func TestCallbackRequiresGET(t *testing.T) {
	p := newOIDCTestProvider(t)
	auth := newAuth(t, p, nil)

	rw := httptest.NewRecorder()
	auth.ServeHTTP(rw, httptest.NewRequest(http.MethodPost, "https://app.test/callback?code=x&state=y", nil))

	if rw.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rw.Code)
	}
	if got := p.capturedForm(); got != nil {
		t.Fatalf("token endpoint was called on a non-GET callback: %v", got)
	}
}

// TestCallbackRejectsUnknownState fails a callback whose state was never issued.
func TestCallbackRejectsUnknownState(t *testing.T) {
	p := newOIDCTestProvider(t)
	auth := newAuth(t, p, nil)

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app.test/callback?code=CODE&state=never-issued", nil)
	req.AddCookie(&http.Cookie{Name: loginCookieName(auth.clientKey, "never-issued"), Value: "never-issued"})
	auth.ServeHTTP(rw, req)

	if rw.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rw.Code)
	}
	if _, ok := auth.SessionStore.Get("any"); ok {
		t.Fatal("no session should be created for an unknown state")
	}
}

// TestCallbackRequiresLoginCookie fails a callback whose state has no matching
// state-bound login cookie, proving the cookie is required before exchange.
func TestCallbackRequiresLoginCookie(t *testing.T) {
	p := newOIDCTestProvider(t)
	auth := newAuth(t, p, nil)

	state := startLogin(t, auth, "/dashboard")

	rw := httptest.NewRecorder()
	auth.ServeHTTP(rw, httptest.NewRequest(http.MethodGet, "https://app.test/callback?code=CODE&state="+state, nil))

	if rw.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rw.Code)
	}
	if got := p.capturedForm(); got != nil {
		t.Fatalf("token endpoint was called without a login cookie: %v", got)
	}
}

// TestCallbackRejectsReplay redeems a state once and asserts a second
// callback with the same state (and login cookie) cannot succeed.
func TestCallbackRejectsReplay(t *testing.T) {
	p := newOIDCTestProvider(t)
	auth := newAuth(t, p, nil)

	state := startLogin(t, auth, "/dashboard")
	nonce, _ := peekLogin(t, auth, state)

	p.setToken(validTokenResponse(p, nonce, "access-token"))
	do := func() *httptest.ResponseRecorder {
		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://app.test/callback?code=CODE&state="+state, nil)
		req.AddCookie(&http.Cookie{Name: loginCookieName(auth.clientKey, state), Value: state})
		auth.ServeHTTP(rw, req)
		return rw
	}

	if rw := do(); rw.Code != http.StatusSeeOther {
		t.Fatalf("first callback status = %d, want 303", rw.Code)
	}
	if rw := do(); rw.Code != http.StatusBadRequest {
		t.Fatalf("replayed callback status = %d, want 400", rw.Code)
	}
}

// TestCallbackProcessedBeforeExistingSession proves the callback path is
// handled even when a valid session cookie is present.
func TestCallbackProcessedBeforeExistingSession(t *testing.T) {
	p := newOIDCTestProvider(t)
	auth := newAuth(t, p, nil)

	sessionID := completeLogin(t, auth, p, "/")
	cap := &capture{}
	auth.next = cap.handler()

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app.test/callback", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName(auth.clientKey), Value: sessionID})
	auth.ServeHTTP(rw, req)

	if cap.called {
		t.Fatal("callback path must be processed before existing sessions, not forwarded")
	}
	// With no code/state the callback fails closed rather than forwarding or
	// starting a login.
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a callback with no code/state", rw.Code)
	}
}

// TestCallbackMissingCodeReturns400 proves a callback without a code answers
// 400 even for a navigation request, without redirecting or creating a login.
func TestCallbackMissingCodeReturns400(t *testing.T) {
	p := newOIDCTestProvider(t)
	auth := newAuth(t, p, nil)

	rw := httptest.NewRecorder()
	req := navigationGet("https://app.test/callback?state=whatever")
	auth.ServeHTTP(rw, req)

	if rw.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (no code)", rw.Code)
	}
	if loc := rw.Header().Get("Location"); loc != "" {
		t.Fatalf("Location = %q, want no redirect for a missing-code callback", loc)
	}
	auth.loginStore.mu.Lock()
	n := len(auth.loginStore.byState)
	auth.loginStore.mu.Unlock()
	if n != 0 {
		t.Fatalf("login store holds %d transactions, want none created for a missing-code callback", n)
	}
}

// TestCallbackMissingStateReturns400 proves a callback without a state answers
// 400 for an API request, without creating a login.
func TestCallbackMissingStateReturns400(t *testing.T) {
	p := newOIDCTestProvider(t)
	auth := newAuth(t, p, nil)

	rw := httptest.NewRecorder()
	req := apiGet("https://app.test/callback?code=CODE")
	auth.ServeHTTP(rw, req)

	if rw.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (no state)", rw.Code)
	}
	if loc := rw.Header().Get("Location"); loc != "" {
		t.Fatalf("Location = %q, want no redirect for a missing-state callback", loc)
	}
	auth.loginStore.mu.Lock()
	n := len(auth.loginStore.byState)
	auth.loginStore.mu.Unlock()
	if n != 0 {
		t.Fatalf("login store holds %d transactions, want none created for a missing-state callback", n)
	}
}

// TestCallbackProcessedBeforeIgnoredPath proves the callback path wins over an
// ignored-path match for the same path.
func TestCallbackProcessedBeforeIgnoredPath(t *testing.T) {
	p := newOIDCTestProvider(t)
	auth := newAuth(t, p, func(c *Config) {
		c.CallbackURL = "https://app.test/healthz"
		c.IgnorePathPrefixes = "/healthz"
	})

	state := startLogin(t, auth, "/")
	nonce, _ := peekLogin(t, auth, state)
	p.setToken(validTokenResponse(p, nonce, "access-token"))

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app.test/healthz?code=CODE&state="+state, nil)
	req.AddCookie(&http.Cookie{Name: loginCookieName(auth.clientKey, state), Value: state})
	auth.ServeHTTP(rw, req)

	if rw.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303 (callback handled, not ignored)", rw.Code)
	}
	found := false
	for _, c := range rw.Result().Cookies() {
		if c.Name == sessionCookieName(auth.clientKey) {
			found = true
			if _, ok := auth.SessionStore.Get(c.Value); !ok {
				t.Fatal("session cookie must map to a stored session")
			}
		}
	}
	if !found {
		t.Fatal("expected session cookie from callback despite matching ignored path")
	}
}

// TestCallbackValidatesIss rejects a callback whose iss parameter differs from
// the configured issuer.
func TestCallbackValidatesIss(t *testing.T) {
	p := newOIDCTestProvider(t)
	auth := newAuth(t, p, nil)

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app.test/callback?code=CODE&state=s&iss=https://evil.test/realms/r", nil)
	req.AddCookie(&http.Cookie{Name: loginCookieName(auth.clientKey, "s"), Value: "s"})
	auth.ServeHTTP(rw, req)

	if rw.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for iss mismatch", rw.Code)
	}
	if got := p.capturedForm(); got != nil {
		t.Fatalf("token endpoint was called on iss mismatch: %v", got)
	}
}

// TestLoginURLUsesPKCEAndNonce asserts the auth redirect carries S256 PKCE and
// a nonce, and that the exchange sends the matching verifier.
func TestLoginURLUsesPKCEAndNonce(t *testing.T) {
	p := newOIDCTestProvider(t)
	auth := newAuth(t, p, nil)

	rw := httptest.NewRecorder()
	auth.ServeHTTP(rw, navigationGet("https://app.test/dashboard"))
	if rw.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rw.Code)
	}
	loc, err := url.Parse(rw.Header().Get("Location"))
	if err != nil {
		t.Fatalf("unparseable Location: %v", err)
	}
	q := loc.Query()
	if q.Get("code_challenge_method") != "S256" {
		t.Fatalf("code_challenge_method = %q, want S256", q.Get("code_challenge_method"))
	}
	if q.Get("code_challenge") == "" {
		t.Fatal("auth URL missing code_challenge")
	}
	if q.Get("nonce") == "" {
		t.Fatal("auth URL missing nonce")
	}
	if q.Get("redirect_uri") != "https://app.test/callback" {
		t.Fatalf("redirect_uri = %q, want exact callback", q.Get("redirect_uri"))
	}

	state := q.Get("state")
	nonce, verifier := peekLogin(t, auth, state)
	if want := pkceChallenge(verifier); q.Get("code_challenge") != want {
		t.Fatalf("code_challenge = %q, want S256(verifier) = %q", q.Get("code_challenge"), want)
	}

	p.setToken(validTokenResponse(p, nonce, "access-token"))
	rw = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app.test/callback?code=CODE&state="+state, nil)
	req.AddCookie(&http.Cookie{Name: loginCookieName(auth.clientKey, state), Value: state})
	auth.ServeHTTP(rw, req)

	if got := p.capturedForm().Get("code_verifier"); got != verifier {
		t.Fatalf("code_verifier = %q, want %q", got, verifier)
	}
}

// TestLoginIssuesSecureHostOnlyCookies checks cookie attributes and the
// no-store cache header on plugin responses.
func TestLoginIssuesSecureHostOnlyCookies(t *testing.T) {
	p := newOIDCTestProvider(t)
	auth := newAuth(t, p, nil)

	rw := httptest.NewRecorder()
	auth.ServeHTTP(rw, navigationGet("https://app.test/dashboard"))
	if rw.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rw.Code)
	}
	if cc := rw.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cc)
	}

	cookies := rw.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d, want exactly one login cookie", len(cookies))
	}
	c := cookies[0]
	if !strings.HasPrefix(c.Name, "__Host-") || c.Domain != "" {
		t.Fatalf("login cookie %q must be host-only __Host-", c.Name)
	}
	if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
		t.Fatalf("login cookie attributes wrong: %+v", c)
	}
}

// TestForwardingDerivesUserAndBearer checks a validated session sets the user
// header and, when configured, the Authorization header.
func TestForwardingDerivesUserAndBearer(t *testing.T) {
	p := newOIDCTestProvider(t)
	auth := newAuth(t, p, func(c *Config) { c.UseAuthHeader = true })

	sessionID := completeLogin(t, auth, p, "/")
	cap := &capture{}
	auth.next = cap.handler()

	rw := httptest.NewRecorder()
	req := apiGet("https://app.test/dashboard")
	req.AddCookie(&http.Cookie{Name: sessionCookieName(auth.clientKey), Value: sessionID})
	auth.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK || !cap.called {
		t.Fatalf("status = %d, called = %t; want forwarded", rw.Code, cap.called)
	}
	if cap.user != "alice" {
		t.Fatalf("X-Forwarded-User = %q, want alice", cap.user)
	}
	if cap.authz != "Bearer access-token" {
		t.Fatalf("Authorization = %q, want Bearer access-token", cap.authz)
	}
}

// TestForwardingNoAuthHeaderWhenDisabled confirms Authorization is not set when
// UseAuthHeader is false.
func TestForwardingNoAuthHeaderWhenDisabled(t *testing.T) {
	p := newOIDCTestProvider(t)
	auth := newAuth(t, p, nil)

	sessionID := completeLogin(t, auth, p, "/")
	cap := &capture{}
	auth.next = cap.handler()

	rw := httptest.NewRecorder()
	req := apiGet("https://app.test/dashboard")
	req.AddCookie(&http.Cookie{Name: sessionCookieName(auth.clientKey), Value: sessionID})
	auth.ServeHTTP(rw, req)

	if !cap.called {
		t.Fatal("expected forward")
	}
	if cap.user != "alice" {
		t.Fatalf("X-Forwarded-User = %q, want alice", cap.user)
	}
	if cap.authz != "" {
		t.Fatalf("Authorization = %q, want empty when UseAuthHeader is false", cap.authz)
	}
}

// TestSpoofedHeadersStripped proves incoming user/authorization headers are
// removed before forwarding, replaced only by validated session data.
func TestSpoofedHeadersStripped(t *testing.T) {
	p := newOIDCTestProvider(t)
	auth := newAuth(t, p, func(c *Config) { c.UseAuthHeader = true })

	sessionID := completeLogin(t, auth, p, "/")
	cap := &capture{}
	auth.next = cap.handler()

	rw := httptest.NewRecorder()
	req := apiGet("https://app.test/dashboard")
	req.Header.Set("X-Forwarded-User", "spoofed")
	req.Header.Set("Authorization", "Bearer spoofed")
	req.AddCookie(&http.Cookie{Name: sessionCookieName(auth.clientKey), Value: sessionID})
	auth.ServeHTTP(rw, req)

	if cap.user != "alice" {
		t.Fatalf("X-Forwarded-User = %q, want validated alice (spoofed stripped)", cap.user)
	}
	if cap.authz != "Bearer access-token" {
		t.Fatalf("Authorization = %q, want validated bearer (spoofed stripped)", cap.authz)
	}
}

// TestIgnoredPathStripsHeaders confirms ignored paths receive neither header.
func TestIgnoredPathStripsHeaders(t *testing.T) {
	p := newOIDCTestProvider(t)
	auth := newAuth(t, p, func(c *Config) { c.IgnorePathPrefixes = "/healthz" })
	cap := &capture{}
	auth.next = cap.handler()

	rw := httptest.NewRecorder()
	req := apiGet("https://app.test/healthz")
	req.Header.Set("X-Forwarded-User", "spoofed")
	req.Header.Set("Authorization", "Bearer spoofed")
	auth.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK || !cap.called {
		t.Fatalf("status = %d, called = %t; ignored path must forward", rw.Code, cap.called)
	}
	if cap.user != "" || cap.authz != "" {
		t.Fatalf("ignored path received user=%q authz=%q, want neither", cap.user, cap.authz)
	}
}

// TestIgnoredPathSegmentMatchingIntegration proves substring matches do not
// bypass auth while segment matches do.
func TestIgnoredPathSegmentMatchingIntegration(t *testing.T) {
	p := newOIDCTestProvider(t)
	auth := newAuth(t, p, func(c *Config) { c.IgnorePathPrefixes = "/api" })

	// A substring-only match (e.g. /apix) must still require auth.
	rw := httptest.NewRecorder()
	auth.ServeHTTP(rw, apiGet("https://app.test/apix"))
	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for /apix (not a segment match)", rw.Code)
	}

	// A segment match forwards without auth.
	cap := &capture{}
	auth.next = cap.handler()
	rw = httptest.NewRecorder()
	auth.ServeHTTP(rw, apiGet("https://app.test/api/users"))
	if rw.Code != http.StatusOK || !cap.called {
		t.Fatalf("status = %d, called = %t; /api/users must be ignored", rw.Code, cap.called)
	}
}

// TestMissingSessionNavigation303AndAPI401 checks the navigation/API split.
func TestMissingSessionNavigation303AndAPI401(t *testing.T) {
	p := newOIDCTestProvider(t)
	auth := newAuth(t, p, nil)

	rw := httptest.NewRecorder()
	auth.ServeHTTP(rw, navigationGet("https://app.test/dashboard"))
	if rw.Code != http.StatusSeeOther {
		t.Fatalf("navigation status = %d, want 303", rw.Code)
	}

	rw = httptest.NewRecorder()
	auth.ServeHTTP(rw, apiGet("https://app.test/dashboard"))
	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("api status = %d, want 401", rw.Code)
	}
	if cc := rw.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cc)
	}
	if !strings.Contains(rw.Body.String(), "authentication_required") {
		t.Fatalf("body = %q, want authentication_required", rw.Body.String())
	}

	rw = httptest.NewRecorder()
	auth.ServeHTTP(rw, httptest.NewRequest(http.MethodPost, "https://app.test/dashboard", nil))
	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("POST status = %d, want 401", rw.Code)
	}
}

// TestMalformedIdentityFailsClosed proves a missing or non-string user claim
// fails closed without calling next.
func TestMalformedIdentityFailsClosed(t *testing.T) {
	p := newOIDCTestProvider(t)
	auth := newAuth(t, p, func(c *Config) { c.UserClaimName = "missing_claim" })

	sessionID := completeLogin(t, auth, p, "/")
	cap := &capture{}
	auth.next = cap.handler()

	rw := httptest.NewRecorder()
	req := apiGet("https://app.test/dashboard")
	req.AddCookie(&http.Cookie{Name: sessionCookieName(auth.clientKey), Value: sessionID})
	auth.ServeHTTP(rw, req)

	if cap.called {
		t.Fatal("next must not be called when the identity claim is missing")
	}
	if rw.Code == http.StatusOK {
		t.Fatalf("status = %d, want fail closed (non-2xx)", rw.Code)
	}
}

// TestInactiveButUnexpiredForcesRenewal proves an inactive token renews even
// when the local expiry is far in the future.
func TestInactiveButUnexpiredForcesRenewal(t *testing.T) {
	p := newOIDCTestProvider(t)
	auth := newAuth(t, p, func(c *Config) { c.UseAuthHeader = true })
	cap := &capture{}
	auth.next = cap.handler()

	auth.SessionStore.Set("known", &Session{
		AccessToken:  "old",
		RefreshToken: "rt1",
		ExpiresAt:    time.Now().Add(time.Hour),
		Subject:      "user-123",
		Claims:       map[string]any{"preferred_username": "alice"},
	})

	p.introspectBody = `{"active":false}`
	p.setToken(marshalTokenResponse("new-access", "new-refresh", "", 300, nil))

	rw := httptest.NewRecorder()
	req := apiGet("https://app.test/dashboard")
	req.AddCookie(&http.Cookie{Name: sessionCookieName(auth.clientKey), Value: "known"})
	auth.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK || !cap.called {
		t.Fatalf("status = %d, called = %t; want renewed and forwarded", rw.Code, cap.called)
	}
	if cap.authz != "Bearer new-access" {
		t.Fatalf("Authorization = %q, want renewed token", cap.authz)
	}
}

// TestNearExpiryRenewsProactively proves a near-expiry active token renews.
func TestNearExpiryRenewsProactively(t *testing.T) {
	p := newOIDCTestProvider(t)
	auth := newAuth(t, p, func(c *Config) { c.UseAuthHeader = true })
	cap := &capture{}
	auth.next = cap.handler()

	auth.SessionStore.Set("known", &Session{
		AccessToken:  "old",
		RefreshToken: "rt1",
		ExpiresAt:    time.Now().Add(10 * time.Second),
		Subject:      "user-123",
		Claims:       map[string]any{"preferred_username": "alice"},
	})

	p.setToken(marshalTokenResponse("new-access", "new-refresh", "", 300, nil))

	rw := httptest.NewRecorder()
	req := apiGet("https://app.test/dashboard")
	req.AddCookie(&http.Cookie{Name: sessionCookieName(auth.clientKey), Value: "known"})
	auth.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK || !cap.called {
		t.Fatalf("status = %d, called = %t; want renewed and forwarded", rw.Code, cap.called)
	}
	if cap.authz != "Bearer new-access" {
		t.Fatalf("Authorization = %q, want renewed token", cap.authz)
	}
}

// TestOutageActiveProceedsInactive502 checks outage handling for both token
// states.
func TestOutageActiveProceedsInactive502(t *testing.T) {
	p := newOIDCTestProvider(t)
	auth := newAuth(t, p, nil)
	cap := &capture{}
	auth.next = cap.handler()

	// Active token near expiry: renewal outage lets the request proceed.
	auth.SessionStore.Set("active", &Session{
		AccessToken:  "old",
		RefreshToken: "rt1",
		ExpiresAt:    time.Now().Add(10 * time.Second),
		Subject:      "user-123",
		Claims:       map[string]any{"preferred_username": "alice"},
	})
	p.tokenStatus = http.StatusInternalServerError
	p.setToken(`{"error":"temporarily_unavailable"}`)

	rw := httptest.NewRecorder()
	req := apiGet("https://app.test/dashboard")
	req.AddCookie(&http.Cookie{Name: sessionCookieName(auth.clientKey), Value: "active"})
	auth.ServeHTTP(rw, req)
	if rw.Code != http.StatusOK || !cap.called {
		t.Fatalf("active outage status = %d, called = %t; want proceed", rw.Code, cap.called)
	}

	// Inactive token: renewal outage yields 502.
	auth.SessionStore.Set("inactive", &Session{
		AccessToken:  "old",
		RefreshToken: "rt1",
		ExpiresAt:    time.Now().Add(time.Hour),
		Subject:      "user-123",
		Claims:       map[string]any{"preferred_username": "alice"},
	})
	p.introspectBody = `{"active":false}`

	rw = httptest.NewRecorder()
	req = apiGet("https://app.test/dashboard")
	req.AddCookie(&http.Cookie{Name: sessionCookieName(auth.clientKey), Value: "inactive"})
	auth.ServeHTTP(rw, req)
	if rw.Code != http.StatusBadGateway {
		t.Fatalf("inactive outage status = %d, want 502", rw.Code)
	}
}

// TestIntrospectionOutage502 proves an introspection failure answers 502.
func TestIntrospectionOutage502(t *testing.T) {
	p := newOIDCTestProvider(t)
	auth := newAuth(t, p, nil)
	cap := &capture{}
	auth.next = cap.handler()

	auth.SessionStore.Set("known", &Session{
		AccessToken:  "old",
		RefreshToken: "rt1",
		ExpiresAt:    time.Now().Add(time.Hour),
		Subject:      "user-123",
		Claims:       map[string]any{"preferred_username": "alice"},
	})
	p.introspectStatus = http.StatusInternalServerError

	rw := httptest.NewRecorder()
	req := apiGet("https://app.test/dashboard")
	req.AddCookie(&http.Cookie{Name: sessionCookieName(auth.clientKey), Value: "known"})
	auth.ServeHTTP(rw, req)

	if rw.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rw.Code)
	}
	if cap.called {
		t.Fatal("next must not be called during an introspection outage")
	}
}

// TestRefreshRefusalEndsSession proves a refused refresh terminates the session.
func TestRefreshRefusalEndsSession(t *testing.T) {
	p := newOIDCTestProvider(t)
	auth := newAuth(t, p, nil)

	auth.SessionStore.Set("known", &Session{
		AccessToken:  "old",
		RefreshToken: "rt1",
		ExpiresAt:    time.Now().Add(-time.Second),
		Subject:      "user-123",
		Claims:       map[string]any{"preferred_username": "alice"},
	})
	p.introspectBody = `{"active":false}`
	p.tokenStatus = http.StatusBadRequest
	p.setToken(`{"error":"invalid_grant"}`)

	rw := httptest.NewRecorder()
	req := navigationGet("https://app.test/dashboard")
	req.AddCookie(&http.Cookie{Name: sessionCookieName(auth.clientKey), Value: "known"})
	auth.ServeHTTP(rw, req)

	if rw.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303 login after refusal", rw.Code)
	}
	if _, ok := auth.SessionStore.Get("known"); ok {
		t.Fatal("refused session must be deleted")
	}
	if sc := rw.Header().Get("Set-Cookie"); !strings.Contains(sc, "Max-Age=0") {
		t.Fatalf("Set-Cookie = %q, want cleared session cookie", sc)
	}
}

// TestRefreshRejectsSubjectChange proves a refresh that returns a different
// subject is rejected and ends the session.
func TestRefreshRejectsSubjectChange(t *testing.T) {
	p := newOIDCTestProvider(t)
	auth := newAuth(t, p, nil)

	auth.SessionStore.Set("known", &Session{
		AccessToken:  "old",
		RefreshToken: "rt1",
		ExpiresAt:    time.Now().Add(-time.Second),
		Subject:      "user-123",
		Claims:       map[string]any{"preferred_username": "alice"},
	})
	p.introspectBody = `{"active":false}`

	claims := p.baseClaims()
	claims["sub"] = "evil-user"
	p.setToken(marshalTokenResponse("new-access", "new-refresh", p.signIDToken(claims), 300, nil))

	rw := httptest.NewRecorder()
	req := navigationGet("https://app.test/dashboard")
	req.AddCookie(&http.Cookie{Name: sessionCookieName(auth.clientKey), Value: "known"})
	auth.ServeHTTP(rw, req)

	if rw.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303 (subject change terminates session)", rw.Code)
	}
	if _, ok := auth.SessionStore.Get("known"); ok {
		t.Fatal("session with a changed subject must be terminated")
	}
}

// TestGenericErrorsDoNotLeakBodies proves upstream bodies never reach clients.
func TestGenericErrorsDoNotLeakBodies(t *testing.T) {
	p := newOIDCTestProvider(t)
	auth := newAuth(t, p, nil)

	auth.SessionStore.Set("known", &Session{
		AccessToken:  "old",
		RefreshToken: "rt1",
		ExpiresAt:    time.Now().Add(-time.Second),
		Subject:      "user-123",
		Claims:       map[string]any{"preferred_username": "alice"},
	})
	p.introspectBody = `{"active":false}`
	p.tokenStatus = http.StatusBadRequest
	p.setToken(`{"error":"invalid_grant","error_description":"SECRET_LEAK_MARKER"}`)

	rw := httptest.NewRecorder()
	auth.ServeHTTP(rw, apiGet("https://app.test/dashboard"))
	if strings.Contains(rw.Body.String(), "SECRET_LEAK_MARKER") {
		t.Fatalf("response leaked upstream body: %q", rw.Body.String())
	}
}

// TestSameClientSharing proves two middleware instances for the same client
// share one session store.
func TestSameClientSharing(t *testing.T) {
	resetSharedStores()
	p := newOIDCTestProvider(t)
	first := newAuth(t, p, nil)
	second := newAuth(t, p, nil)

	if first.SessionStore != second.SessionStore {
		t.Fatal("instances of the same client must share one store")
	}

	sessionID := completeLogin(t, first, p, "/")
	cap := &capture{}
	second.next = cap.handler()

	rw := httptest.NewRecorder()
	req := apiGet("https://app.test/dashboard")
	req.AddCookie(&http.Cookie{Name: sessionCookieName(first.clientKey), Value: sessionID})
	second.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK || !cap.called {
		t.Fatalf("status = %d, called = %t; second instance must accept the session", rw.Code, cap.called)
	}
}

// TestDifferentClientIsolation proves distinct clients never share sessions.
func TestDifferentClientIsolation(t *testing.T) {
	resetSharedStores()
	p := newOIDCTestProvider(t)
	first := newAuth(t, p, nil)
	second := newAuth(t, p, func(c *Config) { c.ClientID = "other-client" })

	if first.SessionStore == second.SessionStore {
		t.Fatal("distinct clients must have distinct stores")
	}

	first.SessionStore.Set("known", &Session{AccessToken: "a", RefreshToken: "rt", ExpiresAt: time.Now().Add(time.Hour)})

	rw := httptest.NewRecorder()
	req := apiGet("https://app.test/dashboard")
	req.AddCookie(&http.Cookie{Name: sessionCookieName(first.clientKey), Value: "known"})
	second.ServeHTTP(rw, req)

	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (session must not cross clients)", rw.Code)
	}
}

// TestReloadPersistence proves sessions survive middleware recreation, as on a
// Traefik dynamic configuration reload.
func TestReloadPersistence(t *testing.T) {
	resetSharedStores()
	p := newOIDCTestProvider(t)

	first := newAuth(t, p, nil)
	sessionID := completeLogin(t, first, p, "/")

	second := newAuth(t, p, nil)
	cap := &capture{}
	second.next = cap.handler()

	rw := httptest.NewRecorder()
	req := apiGet("https://app.test/dashboard")
	req.AddCookie(&http.Cookie{Name: sessionCookieName(first.clientKey), Value: sessionID})
	second.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK || !cap.called {
		t.Fatalf("status = %d, called = %t; session must survive reload", rw.Code, cap.called)
	}
}

// TestReloadAdjustsCapacity proves an existing store adopts a new valid
// capacity on recreation.
func TestReloadAdjustsCapacity(t *testing.T) {
	resetSharedStores()
	p := newOIDCTestProvider(t)

	first := newAuth(t, p, func(c *Config) { c.SessionCapacity = 2 })
	for _, id := range []string{"a", "b"} {
		first.SessionStore.Set(id, &Session{AccessToken: id})
	}

	second := newAuth(t, p, func(c *Config) { c.SessionCapacity = 1 })
	if _, ok := second.SessionStore.Get("a"); ok {
		t.Fatal("shrinking capacity on reload must evict the least recently used session")
	}
	if _, ok := second.SessionStore.Get("b"); !ok {
		t.Fatal("the most recently used session must survive the shrink")
	}
}
