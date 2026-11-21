package keycloakopenid

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func testConfig() *Config {
	config := CreateConfig()
	config.KeycloakURL = "http://127.0.0.1:1"
	config.ClientID = "c"
	config.ClientSecret = "s"
	config.KeycloakRealm = "r"
	config.CallbackURL = "https://app.test/callback"
	return config
}

func newTestAuth(t *testing.T, config *Config) *keycloakAuth {
	t.Helper()
	handler, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), config, "test")
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	auth, ok := handler.(*keycloakAuth)
	if !ok {
		t.Fatalf("handler is %T, want *keycloakAuth", handler)
	}
	return auth
}

func newConfigError(t *testing.T, config *Config, want string) {
	t.Helper()
	_, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), config, "test")
	if err == nil {
		t.Fatal("New returned nil error, want error")
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("New error = %q, want it to contain %q", err, want)
	}
}

// newProviderAuth returns a middleware backed by a fresh OIDC test provider,
// applying mutate to the configuration before construction.
func newProviderAuth(t *testing.T, mutate func(*Config)) *keycloakAuth {
	t.Helper()
	p := newOIDCTestProvider(t)
	config := testConfig()
	config.KeycloakURL = p.srv.URL
	config.ClientID = p.clientID
	if mutate != nil {
		mutate(config)
	}
	return newTestAuth(t, config)
}

func TestConfigRequiresCallbackURL(t *testing.T) {
	config := testConfig()
	config.CallbackURL = ""
	newConfigError(t, config, "callback")
}

func TestConfigRequiresClientSecret(t *testing.T) {
	p := newOIDCTestProvider(t)
	config := testConfig()
	config.KeycloakURL = p.srv.URL
	config.ClientID = p.clientID
	config.ClientSecret = ""
	newConfigError(t, config, "invalid configuration")
}

func TestConfigDefaultSessionCapacity(t *testing.T) {
	auth := newProviderAuth(t, nil)
	if auth.SessionStore.capacity != 10000 {
		t.Fatalf("capacity = %d, want 10000", auth.SessionStore.capacity)
	}
}

func TestConfigZeroSessionCapacityRejected(t *testing.T) {
	config := testConfig()
	config.SessionCapacity = 0
	newConfigError(t, config, "session capacity")
}

func TestConfigNegativeSessionCapacityRejected(t *testing.T) {
	config := testConfig()
	config.SessionCapacity = -1
	newConfigError(t, config, "session capacity")
}

func TestConfigPositiveSessionCapacityAccepted(t *testing.T) {
	auth := newProviderAuth(t, func(c *Config) { c.SessionCapacity = 5 })
	if auth.SessionStore.capacity != 5 {
		t.Fatalf("capacity = %d, want 5", auth.SessionStore.capacity)
	}
}

func TestConfigDefaultRefreshWindow(t *testing.T) {
	auth := newProviderAuth(t, nil)
	if auth.RefreshBeforeExpiry != 30*time.Second {
		t.Fatalf("RefreshBeforeExpiry = %v, want 30s", auth.RefreshBeforeExpiry)
	}
}

func TestConfigRefreshWindowParsed(t *testing.T) {
	auth := newProviderAuth(t, func(c *Config) { c.RefreshBeforeExpiry = "45s" })
	if auth.RefreshBeforeExpiry != 45*time.Second {
		t.Fatalf("RefreshBeforeExpiry = %v, want 45s", auth.RefreshBeforeExpiry)
	}
}

func TestConfigInvalidRefreshWindowRejected(t *testing.T) {
	config := testConfig()
	config.RefreshBeforeExpiry = "nope"
	newConfigError(t, config, "RefreshBeforeExpiry")
}

func TestEnsureOpenIDScope(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "openid"},
		{"profile email", "openid profile email"},
		{"openid profile", "openid profile"},
		{"openid", "openid"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := ensureOpenIDScope(tc.in); got != tc.want {
				t.Fatalf("ensureOpenIDScope(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestConfigIgnorePathPrefixesTrimmed(t *testing.T) {
	auth := newProviderAuth(t, func(c *Config) { c.IgnorePathPrefixes = " /api , /favicon.ico " })
	want := []string{"/api", "/favicon.ico"}
	if len(auth.IgnorePathPrefixes) != len(want) {
		t.Fatalf("IgnorePathPrefixes = %v, want %v", auth.IgnorePathPrefixes, want)
	}
	for i := range want {
		if auth.IgnorePathPrefixes[i] != want[i] {
			t.Fatalf("IgnorePathPrefixes[%d] = %q, want %q", i, auth.IgnorePathPrefixes[i], want[i])
		}
	}
}

func TestConfigIgnorePathPrefixesRejectEmpty(t *testing.T) {
	config := testConfig()
	config.IgnorePathPrefixes = "/api,,/favicon.ico"
	newConfigError(t, config, "ignore path prefix")
}

func TestConfigIgnorePathPrefixesRejectMalformed(t *testing.T) {
	config := testConfig()
	config.IgnorePathPrefixes = "api"
	newConfigError(t, config, "ignore path prefix")
}

func TestParseURLSchemes(t *testing.T) {
	valid := []string{"https://kc.test", "http://127.0.0.1:8080", "http://localhost:8080", "http://app.localhost:8080"}
	for _, raw := range valid {
		t.Run("valid "+raw, func(t *testing.T) {
			if _, err := parseUrl(raw); err != nil {
				t.Fatalf("parseUrl(%q) = %v, want no error", raw, err)
			}
		})
	}
	invalid := []string{
		"ftp://kc.test",
		"httpsfoo://kc.test",
		"file:///etc/passwd",
		"http://kc.test",
		"https://user@kc.test",
		"https://kc.test/realm?x=1",
		"https://kc.test/realm#fragment",
		"https:///missing-host",
	}
	for _, raw := range invalid {
		t.Run("invalid "+raw, func(t *testing.T) {
			if _, err := parseUrl(raw); err == nil {
				t.Fatalf("parseUrl(%q) = nil, want error", raw)
			}
		})
	}
}

func TestCanonicalKeycloakURL(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"https://EXAMPLE.COM:443/auth/", "https://example.com/auth"},
		{"http://EXAMPLE.COM:80/auth//", "http://example.com/auth"},
		{"https://EXAMPLE.COM/", "https://example.com"},
		{"https://EXAMPLE.COM:8443/auth/", "https://example.com:8443/auth"},
		{"https://EXAMPLE.COM/auth/../base/", "https://example.com/base"},
		{"https://EXAMPLE.COM/foo%2Fbar/", "https://example.com/foo%2Fbar"},
		{"https://[2001:DB8::1]:443/auth/", "https://[2001:db8::1]/auth"},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			u, err := url.Parse(tc.raw)
			if err != nil {
				t.Fatalf("url.Parse returned error: %v", err)
			}
			if got := canonicalKeycloakURL(u); got != tc.want {
				t.Fatalf("canonicalKeycloakURL(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestCallbackURLHTTPSRequired(t *testing.T) {
	config := testConfig()
	config.CallbackURL = "http://app.test/callback"
	newConfigError(t, config, "https")
}

func TestCallbackURLLoopbackHTTPAllowed(t *testing.T) {
	for _, raw := range []string{"http://127.0.0.1:8080/cb", "http://localhost/cb", "http://[::1]/cb", "http://helloworld1.localhost/cb"} {
		t.Run(raw, func(t *testing.T) {
			newProviderAuth(t, func(c *Config) { c.CallbackURL = raw })
		})
	}
}

func TestCallbackURLHTTPSAllowed(t *testing.T) {
	auth := newProviderAuth(t, func(c *Config) { c.CallbackURL = "https://app.test/callback" })
	if auth.CallbackURL == nil || auth.CallbackURL.String() != "https://app.test/callback" {
		t.Fatalf("CallbackURL = %v, want https://app.test/callback", auth.CallbackURL)
	}
}

func TestCallbackURLRejectsNonHTTPScheme(t *testing.T) {
	config := testConfig()
	config.CallbackURL = "ftp://app.test/cb"
	newConfigError(t, config, "callback url scheme")
}

func TestValidateCallbackURL(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{"https ok", "https://app.test/cb", false},
		{"http loopback", "http://127.0.0.1/cb", false},
		{"http localhost", "http://localhost/cb", false},
		{"http subdomain localhost", "http://helloworld1.localhost/cb", false},
		{"http non-loopback", "http://app.test/cb", true},
		{"https empty path", "https://app.test", true},
		{"https root path", "https://app.test/", false},
		{"fragment", "https://app.test/cb#fragment", true},
		{"empty fragment", "https://app.test/cb#", true},
		{"encoded hash in path", "https://app.test/cb%23alias", false},
		{"empty", "", true},
		{"ftp", "ftp://app.test/cb", true},
		{"no scheme", "app.test/cb", true},
		{"httpsfoo", "httpsfoo://app.test/cb", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateCallbackURL(tc.raw)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateCallbackURL(%q) err = %v, wantErr = %t", tc.raw, err, tc.wantErr)
			}
		})
	}
}

func TestConfigEnvRefreshWindow(t *testing.T) {
	t.Setenv("TEST_REFRESH_WINDOW", "45s")
	p := newOIDCTestProvider(t)
	config := testConfig()
	config.KeycloakURL = p.srv.URL
	config.ClientID = p.clientID
	config.RefreshBeforeExpiryEnv = "TEST_REFRESH_WINDOW"
	auth := newTestAuth(t, config)
	if auth.RefreshBeforeExpiry != 45*time.Second {
		t.Fatalf("RefreshBeforeExpiry = %v, want 45s", auth.RefreshBeforeExpiry)
	}
}

func TestConfigDerivesIssuerAndClientKey(t *testing.T) {
	p := newOIDCTestProvider(t)
	config := testConfig()
	config.KeycloakURL = p.srv.URL
	config.ClientID = p.clientID
	auth := newTestAuth(t, config)

	wantIssuer := p.srv.URL + "/realms/r"
	if auth.issuer != wantIssuer {
		t.Fatalf("issuer = %q, want %q", auth.issuer, wantIssuer)
	}
	wantKey := strings.Join([]string{p.srv.URL, "r", p.clientID}, "\x00")
	if auth.clientKey != wantKey {
		t.Fatalf("clientKey = %q, want %q", auth.clientKey, wantKey)
	}
}

func TestConfigDefaultUserHeaderAndClaim(t *testing.T) {
	auth := newProviderAuth(t, nil)
	if auth.UserHeaderName != "X-Forwarded-User" {
		t.Fatalf("UserHeaderName = %q, want X-Forwarded-User", auth.UserHeaderName)
	}
	if auth.UserClaimName != "preferred_username" {
		t.Fatalf("UserClaimName = %q, want preferred_username", auth.UserClaimName)
	}
}

func TestConfigCustomUserHeaderAndClaim(t *testing.T) {
	auth := newProviderAuth(t, func(c *Config) {
		c.UserHeaderName = "X-Custom-User"
		c.UserClaimName = "email"
	})
	if auth.UserHeaderName != "X-Custom-User" {
		t.Fatalf("UserHeaderName = %q, want X-Custom-User", auth.UserHeaderName)
	}
	if auth.UserClaimName != "email" {
		t.Fatalf("UserClaimName = %q, want email", auth.UserClaimName)
	}
}

func TestConfigUserHeaderNameValidation(t *testing.T) {
	valid := []string{"X-Forwarded-User", "x-custom-user", "X_Custom!", "X-123"}
	for _, name := range valid {
		t.Run("valid "+name, func(t *testing.T) {
			auth := newProviderAuth(t, func(c *Config) { c.UserHeaderName = name })
			if auth.UserHeaderName != name {
				t.Fatalf("UserHeaderName = %q, want %q", auth.UserHeaderName, name)
			}
		})
	}

	invalid := []string{"", "Authorization", "authorization", "Bad Header", "Bad:Header", "Bad\rHeader", "X-É"}
	for _, name := range invalid {
		t.Run("invalid "+name, func(t *testing.T) {
			if validUserHeaderName(name) {
				t.Fatalf("validUserHeaderName(%q) = true, want false", name)
			}
		})
	}

	for _, name := range invalid[1:] {
		t.Run("reject "+name, func(t *testing.T) {
			for _, useAuthHeader := range []bool{false, true} {
				p := newOIDCTestProvider(t)
				config := testConfig()
				config.KeycloakURL = p.srv.URL
				config.ClientID = p.clientID
				config.UserHeaderName = name
				config.UseAuthHeader = useAuthHeader
				newConfigError(t, config, "user header")
			}
		})
	}
}

func TestConfigUseAuthHeaderEnvStrict(t *testing.T) {
	cases := []struct {
		name    string
		envName string
		set     bool
		value   string
		wantErr bool
		want    bool
	}{
		{"unset", "TEST_USE_AUTH_HEADER_UNSET", false, "", true, true},
		{"empty", "TEST_USE_AUTH_HEADER_EMPTY", true, "", true, true},
		{"malformed", "TEST_USE_AUTH_HEADER_MALFORMED", true, "not-a-bool", true, true},
		{"false", "TEST_USE_AUTH_HEADER_FALSE", true, "false", false, false},
		{"true", "TEST_USE_AUTH_HEADER_TRUE", true, "true", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(tc.envName, tc.value)
			if !tc.set {
				if err := os.Unsetenv(tc.envName); err != nil {
					t.Fatalf("os.Unsetenv returned error: %v", err)
				}
			}

			p := newOIDCTestProvider(t)
			config := testConfig()
			config.KeycloakURL = p.srv.URL
			config.ClientID = p.clientID
			config.UseAuthHeader = true
			config.UseAuthHeaderEnv = tc.envName

			if tc.wantErr {
				newConfigError(t, config, tc.envName)
				return
			}
			auth := newTestAuth(t, config)
			if auth.UseAuthHeader != tc.want {
				t.Fatalf("UseAuthHeader = %t, want %t", auth.UseAuthHeader, tc.want)
			}
		})
	}
}

func TestConfigRejectsNegativeRefreshWindow(t *testing.T) {
	p := newOIDCTestProvider(t)
	config := testConfig()
	config.KeycloakURL = p.srv.URL
	config.ClientID = p.clientID
	config.RefreshBeforeExpiry = "-1s"
	newConfigError(t, config, "RefreshBeforeExpiry")

	config = testConfig()
	config.KeycloakURL = p.srv.URL
	config.ClientID = p.clientID
	config.RefreshBeforeExpiry = "0s"
	auth := newTestAuth(t, config)
	if auth.RefreshBeforeExpiry != 0 {
		t.Fatalf("RefreshBeforeExpiry = %v, want 0s", auth.RefreshBeforeExpiry)
	}
}

func TestIgnorePathPrefixesNormalizeTrailingSlashes(t *testing.T) {
	cases := []struct {
		raw  string
		want []string
	}{
		{"/api/,/healthz//", []string{"/api", "/healthz"}},
		{"/", []string{"/"}},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			auth := newProviderAuth(t, func(c *Config) { c.IgnorePathPrefixes = tc.raw })
			if len(auth.IgnorePathPrefixes) != len(tc.want) {
				t.Fatalf("IgnorePathPrefixes = %v, want %v", auth.IgnorePathPrefixes, tc.want)
			}
			for i := range tc.want {
				if auth.IgnorePathPrefixes[i] != tc.want[i] {
					t.Fatalf("IgnorePathPrefixes[%d] = %q, want %q", i, auth.IgnorePathPrefixes[i], tc.want[i])
				}
			}
		})
	}
}
