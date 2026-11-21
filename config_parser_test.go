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

func TestConfigDefaultsSilentRenewal(t *testing.T) {
	auth := newTestAuth(t, testConfig())
	if !auth.SilentRenewal {
		t.Fatal("SilentRenewal must default to true")
	}
	if auth.RefreshBeforeExpiry != 30*time.Second {
		t.Fatalf("RefreshBeforeExpiry = %v, want 30s", auth.RefreshBeforeExpiry)
	}
}

func TestConfigExplicitFalseRestoresLegacy(t *testing.T) {
	config := testConfig()
	config.SilentRenewal = boolPtr(false)
	auth := newTestAuth(t, config)
	if auth.SilentRenewal {
		t.Fatal("SilentRenewal=false must restore legacy behavior")
	}
}

func TestConfigSilentRenewalParsesWindow(t *testing.T) {
	config := testConfig()
	config.SilentRenewal = boolPtr(true)
	config.RefreshBeforeExpiry = "45s"
	auth := newTestAuth(t, config)
	if !auth.SilentRenewal {
		t.Fatal("SilentRenewal must be true")
	}
	if auth.RefreshBeforeExpiry != 45*time.Second {
		t.Fatalf("RefreshBeforeExpiry = %v, want 45s", auth.RefreshBeforeExpiry)
	}
}

func TestConfigSilentRenewalInvalidWindowRejected(t *testing.T) {
	config := testConfig()
	config.SilentRenewal = boolPtr(true)
	config.RefreshBeforeExpiry = "nope"
	_, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), config, "test")
	if err == nil {
		t.Fatal("expected error for invalid RefreshBeforeExpiry with SilentRenewal enabled")
	}
}

func TestConfigDefaultInvalidWindowRejected(t *testing.T) {
	config := testConfig()
	config.RefreshBeforeExpiry = "nope"
	_, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), config, "test")
	if err == nil {
		t.Fatal("expected error for invalid RefreshBeforeExpiry with default silent renewal")
	}
}

func TestConfigInvalidWindowIgnoredWhenDisabled(t *testing.T) {
	config := testConfig()
	config.SilentRenewal = boolPtr(false)
	config.RefreshBeforeExpiry = "nope"
	newTestAuth(t, config)
}

func TestConfigEnvVariants(t *testing.T) {
	t.Run("values populate", func(t *testing.T) {
		t.Setenv("TEST_SILENT_RENEWAL", "true")
		t.Setenv("TEST_REFRESH_WINDOW", "45s")
		config := testConfig()
		config.SilentRenewalEnv = "TEST_SILENT_RENEWAL"
		config.RefreshBeforeExpiryEnv = "TEST_REFRESH_WINDOW"
		auth := newTestAuth(t, config)
		if !auth.SilentRenewal {
			t.Fatal("SilentRenewal must be true from environment")
		}
		if auth.RefreshBeforeExpiry != 45*time.Second {
			t.Fatalf("RefreshBeforeExpiry = %v, want 45s", auth.RefreshBeforeExpiry)
		}
	})

	t.Run("env false restores legacy", func(t *testing.T) {
		t.Setenv("TEST_SILENT_RENEWAL", "false")
		config := testConfig()
		config.SilentRenewalEnv = "TEST_SILENT_RENEWAL"
		auth := newTestAuth(t, config)
		if auth.SilentRenewal {
			t.Fatal("SilentRenewal=false from environment must restore legacy behavior")
		}
	})

	t.Run("referenced but unset", func(t *testing.T) {
		t.Setenv("TEST_SILENT_RENEWAL_UNSET", "")
		config := testConfig()
		config.SilentRenewalEnv = "TEST_SILENT_RENEWAL_UNSET"
		_, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), config, "test")
		if err == nil {
			t.Fatal("expected error when SilentRenewalEnv references an unset variable")
		}
	})
}
