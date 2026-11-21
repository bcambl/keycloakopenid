package keycloakopenid

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func testConfig() *Config {
	config := CreateConfig()
	config.KeycloakURL = "http://127.0.0.1:1"
	config.ClientID = "c"
	config.ClientSecret = "s"
	config.KeycloakRealm = "r"
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

func newConfigError(t *testing.T, config *Config) error {
	t.Helper()
	_, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), config, "test")
	if err == nil {
		t.Fatal("New returned nil error, want error")
	}
	return err
}

func TestConfigDefaultRefreshWindow(t *testing.T) {
	auth := newTestAuth(t, testConfig())
	if auth.RefreshBeforeExpiry != 30*time.Second {
		t.Fatalf("RefreshBeforeExpiry = %v, want 30s", auth.RefreshBeforeExpiry)
	}
}

func TestConfigRefreshWindowParsed(t *testing.T) {
	config := testConfig()
	config.RefreshBeforeExpiry = "45s"
	auth := newTestAuth(t, config)
	if auth.RefreshBeforeExpiry != 45*time.Second {
		t.Fatalf("RefreshBeforeExpiry = %v, want 45s", auth.RefreshBeforeExpiry)
	}
}

func TestConfigInvalidRefreshWindowRejected(t *testing.T) {
	config := testConfig()
	config.RefreshBeforeExpiry = "nope"
	newConfigError(t, config)
}

func TestConfigDefaultSessionCapacity(t *testing.T) {
	auth := newTestAuth(t, testConfig())
	if auth.SessionCapacity != 10000 {
		t.Fatalf("SessionCapacity = %d, want 10000", auth.SessionCapacity)
	}
}

func TestConfigZeroSessionCapacityRejected(t *testing.T) {
	config := testConfig()
	config.SessionCapacity = 0
	newConfigError(t, config)
}

func TestConfigNegativeSessionCapacityRejected(t *testing.T) {
	config := testConfig()
	config.SessionCapacity = -1
	newConfigError(t, config)
}

func TestConfigPositiveSessionCapacityAccepted(t *testing.T) {
	config := testConfig()
	config.SessionCapacity = 5
	auth := newTestAuth(t, config)
	if auth.SessionCapacity != 5 {
		t.Fatalf("SessionCapacity = %d, want 5", auth.SessionCapacity)
	}
}

func TestConfigOpenIDScopeAlwaysIncluded(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "openid"},
		{"profile email", "openid profile email"},
		{"openid profile", "openid profile"},
		{"openid", "openid"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			config := testConfig()
			config.Scope = tc.in
			auth := newTestAuth(t, config)
			if auth.Scope != tc.want {
				t.Fatalf("Scope = %q, want %q", auth.Scope, tc.want)
			}
		})
	}
}

func TestConfigIgnorePathPrefixesTrimmed(t *testing.T) {
	config := testConfig()
	config.IgnorePathPrefixes = " /api , /favicon.ico "
	auth := newTestAuth(t, config)
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
	newConfigError(t, config)
}

func TestConfigIgnorePathPrefixesRejectMalformed(t *testing.T) {
	config := testConfig()
	config.IgnorePathPrefixes = "api"
	newConfigError(t, config)
}

func TestKeycloakURLExactHTTPSchemes(t *testing.T) {
	valid := []string{"http://kc.test", "https://kc.test", "http://127.0.0.1:8080"}
	for _, raw := range valid {
		t.Run("valid "+raw, func(t *testing.T) {
			config := testConfig()
			config.KeycloakURL = raw
			newTestAuth(t, config)
		})
	}
	invalid := []string{"ftp://kc.test", "httpsfoo://kc.test", "file:///etc/passwd"}
	for _, raw := range invalid {
		t.Run("invalid "+raw, func(t *testing.T) {
			config := testConfig()
			config.KeycloakURL = raw
			newConfigError(t, config)
		})
	}
}

func TestCallbackURLHTTPSRequired(t *testing.T) {
	config := testConfig()
	config.CallbackURL = "http://app.test/callback"
	newConfigError(t, config)
}

func TestCallbackURLLoopbackHTTPAllowed(t *testing.T) {
	for _, raw := range []string{"http://127.0.0.1:8080/cb", "http://localhost/cb", "http://[::1]/cb"} {
		t.Run(raw, func(t *testing.T) {
			config := testConfig()
			config.CallbackURL = raw
			newTestAuth(t, config)
		})
	}
}

func TestCallbackURLHTTPSAllowed(t *testing.T) {
	config := testConfig()
	config.CallbackURL = "https://app.test/callback"
	auth := newTestAuth(t, config)
	if auth.CallbackURL == nil || auth.CallbackURL.String() != "https://app.test/callback" {
		t.Fatalf("CallbackURL = %v, want https://app.test/callback", auth.CallbackURL)
	}
}

func TestCallbackURLRejectsNonHTTPScheme(t *testing.T) {
	config := testConfig()
	config.CallbackURL = "ftp://app.test/cb"
	newConfigError(t, config)
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
		{"http non-loopback", "http://app.test/cb", true},
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
	config := testConfig()
	config.RefreshBeforeExpiryEnv = "TEST_REFRESH_WINDOW"
	auth := newTestAuth(t, config)
	if auth.RefreshBeforeExpiry != 45*time.Second {
		t.Fatalf("RefreshBeforeExpiry = %v, want 45s", auth.RefreshBeforeExpiry)
	}
}
