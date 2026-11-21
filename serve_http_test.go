package keycloakopenid

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func newSessionRequest(method, target, sessionID string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "app.test")
	if sessionID != "" {
		req.AddCookie(&http.Cookie{Name: "SessionID", Value: sessionID})
	}
	return req
}

func navigateRequest(req *http.Request) {
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Accept", "text/html")
}

func apiRequest(req *http.Request) {
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Accept", "application/json")
}

type capturedNext struct {
	called        bool
	authorization string
	user          string
}

func (n *capturedNext) install(auth *keycloakAuth) {
	auth.next = http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		n.called = true
		n.authorization = req.Header.Get("Authorization")
		n.user = req.Header.Get("X-Forwarded-User")
		rw.WriteHeader(http.StatusOK)
	})
}

func callbackState(t *testing.T, redirectURL string) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString([]byte(`{"redirect_url":"` + redirectURL + `"}`))
}

func TestServeHTTPLegacyNoSessionRedirect307(t *testing.T) {
	kc := newTestKeycloak(t)
	auth := newTestMiddleware(t, kc, Config{SilentRenewal: boolPtr(false)})
	rw := httptest.NewRecorder()

	auth.ServeHTTP(rw, newSessionRequest(http.MethodGet, "https://app.test/x", ""))

	if rw.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want 307", rw.Code)
	}
	if loc := rw.Header().Get("Location"); !strings.HasPrefix(loc, kc.srv.URL+"/realms/r/protocol/openid-connect/auth") {
		t.Fatalf("Location = %q, want keycloak auth URL", loc)
	}
	if setCookie := rw.Header().Get("Set-Cookie"); setCookie != "" {
		t.Fatalf("Set-Cookie = %q, want none", setCookie)
	}
}

func TestServeHTTPLegacyStoreMissNoCookieClear(t *testing.T) {
	kc := newTestKeycloak(t)
	auth := newTestMiddleware(t, kc, Config{SilentRenewal: boolPtr(false)})
	rw := httptest.NewRecorder()

	auth.ServeHTTP(rw, newSessionRequest(http.MethodGet, "https://app.test/x", "unknown"))

	if rw.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want 307", rw.Code)
	}
	if setCookie := rw.Header().Get("Set-Cookie"); setCookie != "" {
		t.Fatalf("Set-Cookie = %q, want none (legacy parity)", setCookie)
	}
}

func TestServeHTTPLegacyInactiveClearsCookieAnd307(t *testing.T) {
	kc := newTestKeycloak(t)
	kc.introspectActive = false
	auth := newTestMiddleware(t, kc, Config{SilentRenewal: boolPtr(false)})
	auth.SessionStore.Set("known", &Session{AccessToken: "old", ExpiresAt: time.Now().Add(time.Hour)})
	rw := httptest.NewRecorder()

	auth.ServeHTTP(rw, newSessionRequest(http.MethodGet, "https://app.test/x", "known"))

	if rw.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want 307", rw.Code)
	}
	setCookie := rw.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, "SessionID=;") || !strings.Contains(setCookie, "Max-Age=0") {
		t.Fatalf("Set-Cookie = %q, want cleared SessionID", setCookie)
	}
}

func TestServeHTTPLegacyNeverRefreshes(t *testing.T) {
	kc := newTestKeycloak(t)
	auth := newTestMiddleware(t, kc, Config{SilentRenewal: boolPtr(false)})
	next := &capturedNext{}
	next.install(auth)
	auth.SessionStore.Set("known", &Session{AccessToken: jwtWithClaims(`{"preferred_username":"alice"}`), ExpiresAt: time.Now().Add(10 * time.Second)})
	rw := httptest.NewRecorder()

	auth.ServeHTTP(rw, newSessionRequest(http.MethodGet, "https://app.test/x", "known"))

	if !next.called {
		t.Fatal("expected request to reach the next handler")
	}
	if got := kc.refreshCalls(); got != 0 {
		t.Fatalf("refreshCount = %d, want 0 in legacy mode", got)
	}
	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rw.Code)
	}
}

func TestServeHTTPLegacyIntrospectionTransportError500(t *testing.T) {
	kc := newTestKeycloak(t)
	auth := newTestMiddleware(t, kc, Config{SilentRenewal: boolPtr(false)})
	auth.SessionStore.Set("known", &Session{AccessToken: "old", ExpiresAt: time.Now().Add(time.Hour)})
	kc.srv.Close()
	rw := httptest.NewRecorder()

	auth.ServeHTTP(rw, newSessionRequest(http.MethodGet, "https://app.test/x", "known"))

	if rw.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (legacy parity)", rw.Code)
	}
}

func TestServeHTTPRenewalCallback303StoresTokens(t *testing.T) {
	kc := newTestKeycloak(t)
	auth := newTestMiddleware(t, kc, Config{})
	rw := httptest.NewRecorder()
	state := callbackState(t, "https://app.test/x")
	req := newSessionRequest(http.MethodGet, "https://app.test/x?code=abc&state="+state, "")

	auth.ServeHTTP(rw, req)

	if rw.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rw.Code)
	}
	if loc := rw.Header().Get("Location"); loc != "https://app.test/x" {
		t.Fatalf("Location = %q, want https://app.test/x", loc)
	}
	cookies := rw.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "SessionID" || cookies[0].Value == "" {
		t.Fatalf("cookies = %v, want one SessionID", cookies)
	}
	session, ok := auth.SessionStore.Get(cookies[0].Value)
	if !ok {
		t.Fatal("expected stored session for new cookie")
	}
	if session.AccessToken != "access" || session.RefreshToken != "refresh" {
		t.Fatalf("session tokens = %q/%q, want access/refresh", session.AccessToken, session.RefreshToken)
	}
	remaining := time.Until(session.ExpiresAt)
	if remaining < 295*time.Second || remaining > 305*time.Second {
		t.Fatalf("ExpiresAt is %v away, want about 300s", remaining)
	}
}

func TestServeHTTPLegacyCallback307OneHourExpiry(t *testing.T) {
	kc := newTestKeycloak(t)
	auth := newTestMiddleware(t, kc, Config{SilentRenewal: boolPtr(false)})
	rw := httptest.NewRecorder()
	state := callbackState(t, "https://app.test/x")

	auth.ServeHTTP(rw, newSessionRequest(http.MethodGet, "https://app.test/x?code=abc&state="+state, ""))

	if rw.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want 307 (legacy parity)", rw.Code)
	}
	cookies := rw.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "SessionID" {
		t.Fatalf("cookies = %v, want one SessionID", cookies)
	}
	session, ok := auth.SessionStore.Get(cookies[0].Value)
	if !ok {
		t.Fatal("expected stored session for new cookie")
	}
	remaining := time.Until(session.ExpiresAt)
	if remaining < 55*time.Minute || remaining > 65*time.Minute {
		t.Fatalf("ExpiresAt is %v away, want about 1h (legacy parity)", remaining)
	}
	if session.RefreshToken != "" {
		t.Fatalf("RefreshToken = %q, want empty in legacy mode", session.RefreshToken)
	}
}

func TestServeHTTPRenewalRefreshOnInactive(t *testing.T) {
	kc := newTestKeycloak(t)
	kc.introspectActive = false
	newToken := jwtWithClaims(`{"preferred_username":"alice"}`)
	kc.tokenBody = tokenJSON(newToken, "rt2", 300)
	auth := newTestMiddleware(t, kc, Config{})
	next := &capturedNext{}
	next.install(auth)
	auth.SessionStore.Set("known", &Session{AccessToken: "old", RefreshToken: "rt1", ExpiresAt: time.Now().Add(-time.Second)})
	rw := httptest.NewRecorder()

	auth.ServeHTTP(rw, newSessionRequest(http.MethodGet, "https://app.test/x", "known"))

	if !next.called {
		t.Fatal("expected request to reach the next handler after renewal")
	}
	if next.authorization != "Bearer "+newToken {
		t.Fatalf("Authorization = %q, want renewed bearer", next.authorization)
	}
	if next.user != "alice" {
		t.Fatalf("X-Forwarded-User = %q, want alice", next.user)
	}
	if got := kc.refreshCalls(); got != 1 {
		t.Fatalf("refreshCount = %d, want 1", got)
	}
	if loc := rw.Header().Get("Location"); loc != "" {
		t.Fatalf("Location = %q, want no redirect", loc)
	}
}

func TestServeHTTPRenewalProactiveRefresh(t *testing.T) {
	kc := newTestKeycloak(t)
	newToken := jwtWithClaims(`{"preferred_username":"alice"}`)
	kc.tokenBody = tokenJSON(newToken, "rt2", 300)
	auth := newTestMiddleware(t, kc, Config{})
	next := &capturedNext{}
	next.install(auth)
	auth.SessionStore.Set("known", &Session{AccessToken: "old", RefreshToken: "rt1", ExpiresAt: time.Now().Add(10 * time.Second)})
	rw := httptest.NewRecorder()

	auth.ServeHTTP(rw, newSessionRequest(http.MethodGet, "https://app.test/x", "known"))

	if !next.called {
		t.Fatal("expected request to reach the next handler after proactive renewal")
	}
	if next.authorization != "Bearer "+newToken {
		t.Fatalf("Authorization = %q, want renewed bearer", next.authorization)
	}
	if got := kc.refreshCalls(); got != 1 {
		t.Fatalf("refreshCount = %d, want 1", got)
	}
}

func TestServeHTTPRenewalTerminalNavigation303(t *testing.T) {
	kc := newTestKeycloak(t)
	kc.introspectActive = false
	kc.tokenStatus = http.StatusBadRequest
	kc.tokenBody = `{"error":"invalid_grant"}`
	auth := newTestMiddleware(t, kc, Config{})
	auth.SessionStore.Set("known", &Session{AccessToken: "old", RefreshToken: "rt1", ExpiresAt: time.Now().Add(-time.Second)})
	rw := httptest.NewRecorder()
	req := newSessionRequest(http.MethodGet, "https://app.test/x", "known")
	navigateRequest(req)

	auth.ServeHTTP(rw, req)

	if rw.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rw.Code)
	}
	if loc := rw.Header().Get("Location"); !strings.HasPrefix(loc, kc.srv.URL+"/realms/r/protocol/openid-connect/auth") {
		t.Fatalf("Location = %q, want keycloak auth URL", loc)
	}
	if setCookie := rw.Header().Get("Set-Cookie"); !strings.Contains(setCookie, "SessionID=;") {
		t.Fatalf("Set-Cookie = %q, want cleared SessionID", setCookie)
	}
	if _, ok := auth.SessionStore.Get("known"); ok {
		t.Fatal("terminated session must be deleted from the store")
	}
}

func TestServeHTTPRenewalTerminalAPI401(t *testing.T) {
	kc := newTestKeycloak(t)
	kc.introspectActive = false
	kc.tokenStatus = http.StatusBadRequest
	kc.tokenBody = `{"error":"invalid_grant"}`
	auth := newTestMiddleware(t, kc, Config{})
	auth.SessionStore.Set("known", &Session{AccessToken: "old", RefreshToken: "rt1", ExpiresAt: time.Now().Add(-time.Second)})
	rw := httptest.NewRecorder()
	req := newSessionRequest(http.MethodGet, "https://app.test/x", "known")
	apiRequest(req)

	auth.ServeHTTP(rw, req)

	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rw.Code)
	}
	if loc := rw.Header().Get("Location"); loc != "" {
		t.Fatalf("Location = %q, want none for API", loc)
	}
	if !strings.Contains(rw.Body.String(), "authentication_required") {
		t.Fatalf("body = %q, want authentication_required", rw.Body.String())
	}
	if _, ok := auth.SessionStore.Get("known"); ok {
		t.Fatal("terminated session must be deleted from the store")
	}
}

func TestServeHTTPRenewalTerminalPOST401(t *testing.T) {
	kc := newTestKeycloak(t)
	kc.introspectActive = false
	kc.tokenStatus = http.StatusBadRequest
	kc.tokenBody = `{"error":"invalid_grant"}`
	auth := newTestMiddleware(t, kc, Config{})
	auth.SessionStore.Set("known", &Session{AccessToken: "old", RefreshToken: "rt1", ExpiresAt: time.Now().Add(-time.Second)})
	rw := httptest.NewRecorder()
	req := newSessionRequest(http.MethodPost, "https://app.test/x", "known")
	navigateRequest(req)

	auth.ServeHTTP(rw, req)

	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (POST is never navigation)", rw.Code)
	}
}

func TestServeHTTPRenewalStoreMissClearsCookie(t *testing.T) {
	kc := newTestKeycloak(t)
	auth := newTestMiddleware(t, kc, Config{})
	rw := httptest.NewRecorder()
	req := newSessionRequest(http.MethodGet, "https://app.test/x", "unknown")
	navigateRequest(req)

	auth.ServeHTTP(rw, req)

	setCookie := rw.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, "SessionID=;") || !strings.Contains(setCookie, "Max-Age=0") {
		t.Fatalf("Set-Cookie = %q, want cleared SessionID", setCookie)
	}
	if rw.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rw.Code)
	}
}

func TestServeHTTPRenewalIntrospectionOutage502(t *testing.T) {
	kc := newTestKeycloak(t)
	kc.introspectStatus = http.StatusInternalServerError
	auth := newTestMiddleware(t, kc, Config{})
	next := &capturedNext{}
	next.install(auth)
	auth.SessionStore.Set("known", &Session{AccessToken: "old", RefreshToken: "rt1", ExpiresAt: time.Now().Add(time.Hour)})
	rw := httptest.NewRecorder()

	auth.ServeHTTP(rw, newSessionRequest(http.MethodGet, "https://app.test/x", "known"))

	if rw.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rw.Code)
	}
	if next.called {
		t.Fatal("request must not reach the next handler during outage")
	}

	kc.introspectStatus = http.StatusOK
	rw = httptest.NewRecorder()
	auth.ServeHTTP(rw, newSessionRequest(http.MethodGet, "https://app.test/x", "known"))
	if rw.Code != http.StatusOK || !next.called {
		t.Fatalf("status = %d, next.called = %t; session must survive the outage", rw.Code, next.called)
	}
}

func TestServeHTTPRenewalRefreshNetworkErrorActiveProceeds(t *testing.T) {
	kc := newTestKeycloak(t)
	kc.tokenClose = true
	auth := newTestMiddleware(t, kc, Config{})
	next := &capturedNext{}
	next.install(auth)
	auth.SessionStore.Set("known", &Session{AccessToken: "old", RefreshToken: "rt1", ExpiresAt: time.Now().Add(10 * time.Second)})
	rw := httptest.NewRecorder()

	auth.ServeHTTP(rw, newSessionRequest(http.MethodGet, "https://app.test/x", "known"))

	if rw.Code != http.StatusOK || !next.called {
		t.Fatalf("status = %d, next.called = %t; active token must proceed", rw.Code, next.called)
	}
	if next.authorization != "Bearer old" {
		t.Fatalf("Authorization = %q, want old token", next.authorization)
	}
	if _, ok := auth.SessionStore.Get("known"); !ok {
		t.Fatal("session must survive a temporary refresh failure")
	}
}

func TestServeHTTPRenewalRefreshNetworkErrorInactive502(t *testing.T) {
	kc := newTestKeycloak(t)
	kc.introspectActive = false
	kc.tokenClose = true
	auth := newTestMiddleware(t, kc, Config{})
	next := &capturedNext{}
	next.install(auth)
	auth.SessionStore.Set("known", &Session{AccessToken: "old", RefreshToken: "rt1", ExpiresAt: time.Now().Add(-time.Second)})
	rw := httptest.NewRecorder()

	auth.ServeHTTP(rw, newSessionRequest(http.MethodGet, "https://app.test/x", "known"))

	if rw.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rw.Code)
	}
	if next.called {
		t.Fatal("inactive token must not reach the next handler")
	}
	if _, ok := auth.SessionStore.Get("known"); !ok {
		t.Fatal("session must survive a temporary refresh failure")
	}
}

func TestServeHTTPMissingRefreshTokenErrors(t *testing.T) {
	kc := newTestKeycloak(t)
	kc.tokenBody = tokenJSON("access", "", 300)
	auth := newTestMiddleware(t, kc, Config{})
	rw := httptest.NewRecorder()
	state := callbackState(t, "https://app.test/x")

	auth.ServeHTTP(rw, newSessionRequest(http.MethodGet, "https://app.test/x?code=abc&state="+state, ""))

	if rw.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rw.Code)
	}
	if setCookie := rw.Header().Get("Set-Cookie"); setCookie != "" {
		t.Fatalf("Set-Cookie = %q, want none", setCookie)
	}
}

func TestServeHTTPConcurrentRenewalRace(t *testing.T) {
	kc := newTestKeycloak(t)
	kc.tokenBody = tokenJSON(jwtWithClaims(`{"preferred_username":"alice"}`), "rt2", 300)
	auth := newTestMiddleware(t, kc, Config{})
	auth.next = http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})
	auth.SessionStore.Set("known", &Session{AccessToken: "old", RefreshToken: "rt1", ExpiresAt: time.Now().Add(10 * time.Second)})

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rw := httptest.NewRecorder()
			auth.ServeHTTP(rw, newSessionRequest(http.MethodGet, "https://app.test/x", "known"))
			if rw.Code != http.StatusOK {
				t.Errorf("status = %d, want 200", rw.Code)
			}
		}()
	}
	wg.Wait()
}

func TestServeHTTPRenewalNoCookieAPI401(t *testing.T) {
	kc := newTestKeycloak(t)
	auth := newTestMiddleware(t, kc, Config{})
	rw := httptest.NewRecorder()
	req := newSessionRequest(http.MethodGet, "https://app.test/x", "")
	apiRequest(req)

	auth.ServeHTTP(rw, req)

	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rw.Code)
	}
	if loc := rw.Header().Get("Location"); loc != "" {
		t.Fatalf("Location = %q, want none", loc)
	}
	if setCookie := rw.Header().Get("Set-Cookie"); setCookie != "" {
		t.Fatalf("Set-Cookie = %q, want none when no cookie was supplied", setCookie)
	}
}

func TestServeHTTPRenewalNoCookieNavigation303(t *testing.T) {
	kc := newTestKeycloak(t)
	auth := newTestMiddleware(t, kc, Config{})
	rw := httptest.NewRecorder()
	req := newSessionRequest(http.MethodGet, "https://app.test/x", "")
	navigateRequest(req)

	auth.ServeHTTP(rw, req)

	if rw.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rw.Code)
	}
	if loc := rw.Header().Get("Location"); !strings.HasPrefix(loc, kc.srv.URL+"/realms/r/protocol/openid-connect/auth") {
		t.Fatalf("Location = %q, want keycloak auth URL", loc)
	}
	if setCookie := rw.Header().Get("Set-Cookie"); setCookie != "" {
		t.Fatalf("Set-Cookie = %q, want none when no cookie was supplied", setCookie)
	}
}

func TestServeHTTPRenewalNoCookiePOST401(t *testing.T) {
	kc := newTestKeycloak(t)
	auth := newTestMiddleware(t, kc, Config{})
	rw := httptest.NewRecorder()
	req := newSessionRequest(http.MethodPost, "https://app.test/x", "")
	navigateRequest(req)

	auth.ServeHTTP(rw, req)

	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rw.Code)
	}
}

func TestServeHTTPLegacyCallbackNon200ErrorBody(t *testing.T) {
	kc := newTestKeycloak(t)
	kc.tokenStatus = http.StatusBadRequest
	kc.tokenBody = `{"error":"x"}`
	auth := newTestMiddleware(t, kc, Config{SilentRenewal: boolPtr(false)})
	rw := httptest.NewRecorder()
	state := callbackState(t, "https://app.test/x")

	auth.ServeHTTP(rw, newSessionRequest(http.MethodGet, "https://app.test/x?code=abc&state="+state, ""))

	if rw.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rw.Code)
	}
	want := "received bad response from Keycloak: {\"error\":\"x\"}\n"
	if rw.Body.String() != want {
		t.Fatalf("body = %q, want %q (legacy parity)", rw.Body.String(), want)
	}
}

func TestServeHTTPClassificationTable(t *testing.T) {
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
			req := newSessionRequest(tc.method, "https://app.test/x", "")
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
