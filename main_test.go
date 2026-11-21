package keycloakopenid

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type testKeycloak struct {
	srv              *httptest.Server
	introspectStatus int
	introspectActive bool
	tokenStatus      int
	tokenBody        string
	tokenClose       bool
	refreshDelay     time.Duration
	mu               sync.Mutex
	refreshCount     int
	lastRefreshForm  url.Values
}

func boolPtr(v bool) *bool {
	return &v
}

func tokenJSON(access, refresh string, expiresIn int) string {
	return fmt.Sprintf(`{"access_token":%q,"refresh_token":%q,"expires_in":%d}`, access, refresh, expiresIn)
}

func jwtWithClaims(jsonClaims string) string {
	encoding := base64.StdEncoding.WithPadding(base64.NoPadding)
	header := encoding.EncodeToString([]byte(`{"alg":"none"}`))
	return header + "." + encoding.EncodeToString([]byte(jsonClaims)) + ".sig"
}

func newTestKeycloak(t *testing.T) *testKeycloak {
	t.Helper()
	kc := &testKeycloak{
		introspectStatus: http.StatusOK,
		introspectActive: true,
		tokenStatus:      http.StatusOK,
	}
	kc.tokenBody = tokenJSON("access", "refresh", 300)

	mux := http.NewServeMux()
	mux.HandleFunc("/realms/r/protocol/openid-connect/token", func(rw http.ResponseWriter, req *http.Request) {
		if kc.tokenClose {
			hijacker, ok := rw.(http.Hijacker)
			if ok {
				conn, _, err := hijacker.Hijack()
				if err == nil {
					_ = conn.Close()
				}
				return
			}
		}
		if err := req.ParseForm(); err != nil {
			rw.WriteHeader(http.StatusBadRequest)
			return
		}
		if req.Form.Get("grant_type") == "refresh_token" {
			kc.mu.Lock()
			kc.refreshCount++
			form := url.Values{}
			for key, values := range req.Form {
				form[key] = append([]string(nil), values...)
			}
			kc.lastRefreshForm = form
			kc.mu.Unlock()
			if kc.refreshDelay > 0 {
				time.Sleep(kc.refreshDelay)
			}
		}
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(kc.tokenStatus)
		_, _ = io.WriteString(rw, kc.tokenBody)
	})
	mux.HandleFunc("/realms/r/protocol/openid-connect/token/introspect", func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(kc.introspectStatus)
		_, _ = io.WriteString(rw, fmt.Sprintf(`{"active":%t}`, kc.introspectActive))
	})

	kc.srv = httptest.NewServer(mux)
	t.Cleanup(kc.srv.Close)
	return kc
}

func newTestMiddleware(t *testing.T, kc *testKeycloak, config Config) *keycloakAuth {
	t.Helper()
	config.KeycloakURL = kc.srv.URL
	config.ClientID = "c"
	config.ClientSecret = "s"
	config.KeycloakRealm = "r"
	config.UseAuthHeader = true
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

func (kc *testKeycloak) refreshCalls() int {
	kc.mu.Lock()
	defer kc.mu.Unlock()
	return kc.refreshCount
}

func (kc *testKeycloak) lastForm() url.Values {
	kc.mu.Lock()
	defer kc.mu.Unlock()
	return kc.lastRefreshForm
}

func TestExchangeAuthCodeReturnsFullTokenResponse(t *testing.T) {
	kc := newTestKeycloak(t)
	auth := newTestMiddleware(t, kc, Config{})
	state := base64.StdEncoding.EncodeToString([]byte(`{"redirect_url":"https://app.test/x"}`))

	resp, err := auth.exchangeAuthCode("code", state)
	if err != nil {
		t.Fatalf("exchangeAuthCode returned error: %v", err)
	}
	if resp.AccessToken != "access" {
		t.Fatalf("AccessToken = %q, want access", resp.AccessToken)
	}
	if resp.RefreshToken != "refresh" {
		t.Fatalf("RefreshToken = %q, want refresh", resp.RefreshToken)
	}
	if resp.ExpiresIn != 300 {
		t.Fatalf("ExpiresIn = %d, want 300", resp.ExpiresIn)
	}
}

func TestRefreshAccessTokenUsesRefreshGrant(t *testing.T) {
	kc := newTestKeycloak(t)
	auth := newTestMiddleware(t, kc, Config{})

	if _, err := auth.refreshAccessToken("rt1"); err != nil {
		t.Fatalf("refreshAccessToken returned error: %v", err)
	}
	form := kc.lastForm()
	if got := form.Get("grant_type"); got != "refresh_token" {
		t.Fatalf("grant_type = %q, want refresh_token", got)
	}
	if got := form.Get("refresh_token"); got != "rt1" {
		t.Fatalf("refresh_token = %q, want rt1", got)
	}
	if got := form.Get("client_id"); got != "c" {
		t.Fatalf("client_id = %q, want c", got)
	}
}

func TestRefreshAccessTokenRejectsMissingExpiry(t *testing.T) {
	kc := newTestKeycloak(t)
	kc.tokenBody = tokenJSON("a", "r", 0)
	auth := newTestMiddleware(t, kc, Config{})

	_, err := auth.refreshAccessToken("rt")
	if err == nil || !strings.Contains(err.Error(), "missing expires_in") {
		t.Fatalf("error = %v, want missing expires_in", err)
	}
}

func TestRenewSessionUpdatesTokens(t *testing.T) {
	kc := newTestKeycloak(t)
	kc.tokenBody = tokenJSON("new", "rt2", 300)
	auth := newTestMiddleware(t, kc, Config{})
	s := &Session{AccessToken: "old", RefreshToken: "rt1", ExpiresAt: time.Now().Add(-time.Second)}

	if err := auth.renewSession(s); err != nil {
		t.Fatalf("renewSession returned error: %v", err)
	}
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

func TestRenewSessionSerializedSingleFlight(t *testing.T) {
	kc := newTestKeycloak(t)
	kc.refreshDelay = 50 * time.Millisecond
	auth := newTestMiddleware(t, kc, Config{})
	s := &Session{AccessToken: "old", RefreshToken: "rt1", ExpiresAt: time.Now().Add(-time.Second)}

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errs[idx] = auth.renewSession(s)
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatalf("renewSession returned error: %v", err)
		}
	}
	if got := kc.refreshCalls(); got != 1 {
		t.Fatalf("refreshCount = %d, want 1", got)
	}
}

func TestRenewSessionUsesRotatedRefreshToken(t *testing.T) {
	kc := newTestKeycloak(t)
	kc.tokenBody = tokenJSON("new", "rt2", 300)
	auth := newTestMiddleware(t, kc, Config{})
	s := &Session{AccessToken: "old", RefreshToken: "rt1", ExpiresAt: time.Now().Add(-time.Second)}

	if err := auth.renewSession(s); err != nil {
		t.Fatalf("first renewSession returned error: %v", err)
	}
	s.ExpiresAt = time.Now().Add(-time.Second)
	if err := auth.renewSession(s); err != nil {
		t.Fatalf("second renewSession returned error: %v", err)
	}
	if got := kc.lastForm().Get("refresh_token"); got != "rt2" {
		t.Fatalf("refresh_token = %q, want rotated rt2", got)
	}
	if got := kc.refreshCalls(); got != 2 {
		t.Fatalf("refreshCount = %d, want 2", got)
	}
}

func TestRenewSessionAlreadyRenewedSkips(t *testing.T) {
	kc := newTestKeycloak(t)
	auth := newTestMiddleware(t, kc, Config{})
	s := &Session{AccessToken: "old", RefreshToken: "rt1", ExpiresAt: time.Now().Add(-time.Second)}

	if err := auth.renewSession(s); err != nil {
		t.Fatalf("renewSession returned error: %v", err)
	}
	if err := auth.renewSession(s); err != nil {
		t.Fatalf("second renewSession returned error: %v", err)
	}
	if got := kc.refreshCalls(); got != 1 {
		t.Fatalf("refreshCount = %d, want 1", got)
	}
}

func TestRenewSessionKeepsRefreshTokenWhenNotRotated(t *testing.T) {
	kc := newTestKeycloak(t)
	kc.tokenBody = `{"access_token":"new","expires_in":300}`
	auth := newTestMiddleware(t, kc, Config{})
	s := &Session{AccessToken: "old", RefreshToken: "rt1", ExpiresAt: time.Now().Add(-time.Second)}

	if err := auth.renewSession(s); err != nil {
		t.Fatalf("renewSession returned error: %v", err)
	}
	if s.AccessToken != "new" {
		t.Fatalf("AccessToken = %q, want new", s.AccessToken)
	}
	if s.RefreshToken != "rt1" {
		t.Fatalf("RefreshToken = %q, want rt1 retained when the response omits refresh_token", s.RefreshToken)
	}
}

func TestRenewSessionRejectsMissingAccessToken(t *testing.T) {
	kc := newTestKeycloak(t)
	kc.tokenBody = `{"refresh_token":"rt2","expires_in":300}`
	auth := newTestMiddleware(t, kc, Config{})
	s := &Session{AccessToken: "old", RefreshToken: "rt1", ExpiresAt: time.Now().Add(-time.Second)}

	err := auth.renewSession(s)
	if err == nil || !strings.Contains(err.Error(), "missing access_token") {
		t.Fatalf("error = %v, want missing access_token", err)
	}
	if s.AccessToken != "old" || s.RefreshToken != "rt1" {
		t.Fatalf("session mutated on malformed refresh response: %+v", s)
	}
}

func TestIsRefreshRefused(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"invalid grant 400", &keycloakError{Status: 400, Body: `{"error":"invalid_grant"}`}, true},
		{"invalid grant 401", &keycloakError{Status: 401, Body: `{"error":"invalid_grant"}`}, true},
		{"invalid grant 500", &keycloakError{Status: 500, Body: `{"error":"invalid_grant"}`}, false},
		{"invalid client 400", &keycloakError{Status: 400, Body: `{"error":"invalid_client"}`}, false},
		{"plain error", errors.New("boom"), false},
		{"network error", &net.DNSError{IsTimeout: true}, false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRefreshRefused(tc.err); got != tc.want {
				t.Fatalf("isRefreshRefused = %t, want %t", got, tc.want)
			}
		})
	}
}
