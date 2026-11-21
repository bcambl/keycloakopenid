package keycloakopenid

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewUpstreamHTTPClientTimeout(t *testing.T) {
	client := newUpstreamHTTPClient(false)
	if client.Timeout != 10*time.Second {
		t.Fatalf("Timeout = %v, want 10s", client.Timeout)
	}
}

func TestNewUpstreamHTTPClientUsesExplicitTransport(t *testing.T) {
	original := http.DefaultTransport
	http.DefaultTransport = nil
	defer func() {
		http.DefaultTransport = original
		if recovered := recover(); recovered != nil {
			t.Fatalf("newUpstreamHTTPClient panicked with an unavailable default transport: %v", recovered)
		}
	}()

	client := newUpstreamHTTPClient(true)
	bounded, ok := client.Transport.(*boundedRoundTripper)
	if !ok {
		t.Fatalf("Transport = %T, want *boundedRoundTripper", client.Transport)
	}
	transport := bounded.base
	if transport == nil {
		t.Fatal("base transport is nil")
	}
	if transport.Proxy == nil {
		t.Fatal("Proxy is nil, want environment proxy support")
	}
	if !transport.ForceAttemptHTTP2 {
		t.Fatal("ForceAttemptHTTP2 = false, want true")
	}
	if transport.TLSHandshakeTimeout != 10*time.Second {
		t.Fatalf("TLSHandshakeTimeout = %v, want 10s", transport.TLSHandshakeTimeout)
	}
	if transport.IdleConnTimeout != 90*time.Second {
		t.Fatalf("IdleConnTimeout = %v, want 90s", transport.IdleConnTimeout)
	}
	if transport.MaxIdleConns != 100 {
		t.Fatalf("MaxIdleConns = %d, want 100", transport.MaxIdleConns)
	}
	if transport.ExpectContinueTimeout != time.Second {
		t.Fatalf("ExpectContinueTimeout = %v, want 1s", transport.ExpectContinueTimeout)
	}
	if transport.TLSClientConfig == nil || !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("TLSClientConfig does not preserve configured InsecureSkipVerify")
	}
}

func TestNewUpstreamHTTPClientRefusesRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		http.Redirect(rw, req, "/final", http.StatusFound)
	}))
	defer srv.Close()

	client := newUpstreamHTTPClient(false)
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302 (redirect refused)", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/final" {
		t.Fatalf("Location = %q, want /final", loc)
	}
}

func TestNewUpstreamHTTPClientBoundedBody(t *testing.T) {
	big := strings.Repeat("x", (1<<20)+1)
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		_, _ = io.WriteString(rw, big)
	}))
	defer srv.Close()

	client := newUpstreamHTTPClient(false)
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != errResponseTooLarge {
		t.Fatalf("ReadAll err = %v, want errResponseTooLarge", err)
	}
	if len(body) != 1<<20 {
		t.Fatalf("body length = %d, want 1 MiB", len(body))
	}
}

func TestNewUpstreamHTTPClientUnderLimitBody(t *testing.T) {
	small := strings.Repeat("y", 1024)
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		_, _ = io.WriteString(rw, small)
	}))
	defer srv.Close()

	client := newUpstreamHTTPClient(false)
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll returned error: %v", err)
	}
	if string(body) != small {
		t.Fatalf("body = %q, want %q", body, small)
	}
}

func TestNewUpstreamHTTPClientCancellation(t *testing.T) {
	blocking := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		<-blocking
	}))
	defer srv.Close()
	defer close(blocking)

	client := newUpstreamHTTPClient(false)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	if _, err := client.Do(req); err == nil {
		t.Fatal("expected cancellation error")
	}
}

func TestNewUpstreamHTTPClientDoesNotMutateDefaultTransport(t *testing.T) {
	defaultTr := http.DefaultTransport.(*http.Transport)
	before := defaultTr.TLSClientConfig
	client := newUpstreamHTTPClient(true)
	if defaultTr.TLSClientConfig != before {
		t.Fatal("DefaultTransport TLSClientConfig was mutated")
	}
	if client.Transport == http.DefaultTransport {
		t.Fatal("client must not use DefaultTransport directly")
	}
}
