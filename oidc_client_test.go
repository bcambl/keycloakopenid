package keycloakopenid

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// oidcTestProvider serves a discovery document, a JWKS, a token endpoint, and
// an introspection endpoint, signing ID tokens with an in-memory RSA key.
type oidcTestProvider struct {
	srv      *httptest.Server
	issuer   string
	clientID string

	key *rsa.PrivateKey
	kid string

	mu                  sync.Mutex
	discoveryStatus     int
	discoveryAlgorithms []string
	discoveryBody       string

	jwksStatus   int
	jwksBody     string
	jwksRequests int

	tokenStatus      int
	tokenBody        string
	tokenContentType string
	tokenForm        url.Values
	tokenRequests    int
	tokenStarted     chan struct{}
	tokenRelease     chan struct{}

	introspectStatus   int
	introspectBody     string
	introspectRequests int
	introspectObserved chan struct{}
	introspectRelease  chan struct{}
}

func newOIDCTestProvider(t *testing.T) *oidcTestProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey returned error: %v", err)
	}
	p := &oidcTestProvider{
		clientID:            "client-id",
		key:                 key,
		kid:                 "test-key-1",
		discoveryStatus:     http.StatusOK,
		discoveryAlgorithms: []string{"RS256"},
		jwksStatus:          http.StatusOK,
		tokenStatus:         http.StatusOK,
		introspectStatus:    http.StatusOK,
	}
	p.srv = httptest.NewServer(http.HandlerFunc(p.handle))
	t.Cleanup(p.srv.Close)
	p.issuer = p.srv.URL + "/realms/r"
	return p
}

func (p *oidcTestProvider) handle(rw http.ResponseWriter, req *http.Request) {
	switch req.URL.Path {
	case "/realms/r/.well-known/openid-configuration":
		p.serveDiscovery(rw)
	case "/jwks":
		p.serveJWKS(rw)
	case "/realms/r/protocol/openid-connect/token":
		p.serveToken(rw, req)
	case "/realms/r/protocol/openid-connect/token/introspect":
		p.serveIntrospect(rw)
	default:
		http.NotFound(rw, req)
	}
}

func (p *oidcTestProvider) serveDiscovery(rw http.ResponseWriter) {
	p.mu.Lock()
	status := p.discoveryStatus
	body := p.discoveryBody
	algs := p.discoveryAlgorithms
	p.mu.Unlock()

	rw.Header().Set("Content-Type", "application/json")
	if body == "" {
		doc := map[string]any{
			"issuer":                                p.issuer,
			"authorization_endpoint":                p.issuer + "/protocol/openid-connect/auth",
			"token_endpoint":                        p.issuer + "/protocol/openid-connect/token",
			"introspection_endpoint":                p.issuer + "/protocol/openid-connect/token/introspect",
			"jwks_uri":                              p.srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": algs,
		}
		body = mustJSON(doc)
	}
	rw.WriteHeader(status)
	_, _ = rw.Write([]byte(body))
}

func (p *oidcTestProvider) serveJWKS(rw http.ResponseWriter) {
	p.mu.Lock()
	p.jwksRequests++
	status := p.jwksStatus
	body := p.jwksBody
	p.mu.Unlock()
	if body == "" {
		n := base64.RawURLEncoding.EncodeToString(p.key.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.key.E)).Bytes())
		body = fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":%q,"alg":"RS256","use":"sig","n":%q,"e":%q}]}`, p.kid, n, e)
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	_, _ = rw.Write([]byte(body))
}

func (p *oidcTestProvider) serveToken(rw http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	p.tokenForm = req.PostForm
	p.tokenRequests++
	requestNumber := p.tokenRequests
	status := p.tokenStatus
	body := p.tokenBody
	contentType := p.tokenContentType
	started := p.tokenStarted
	release := p.tokenRelease
	p.mu.Unlock()

	if requestNumber == 1 && started != nil {
		close(started)
		<-release
	}
	if contentType == "" {
		contentType = "application/json"
	}
	rw.Header().Set("Content-Type", contentType)
	rw.WriteHeader(status)
	_, _ = rw.Write([]byte(body))
}

func (p *oidcTestProvider) serveIntrospect(rw http.ResponseWriter) {
	p.mu.Lock()
	p.introspectRequests++
	status := p.introspectStatus
	body := p.introspectBody
	observed := p.introspectObserved
	release := p.introspectRelease
	p.mu.Unlock()
	if observed != nil {
		observed <- struct{}{}
	}
	if release != nil {
		<-release
	}
	if body == "" {
		body = `{"active":true}`
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	_, _ = rw.Write([]byte(body))
}

func (p *oidcTestProvider) signIDToken(claims map[string]any) string {
	enc := base64.RawURLEncoding
	header := `{"alg":"RS256","typ":"JWT","kid":"` + p.kid + `"}`
	payload, _ := json.Marshal(claims)
	signingInput := enc.EncodeToString([]byte(header)) + "." + enc.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, digest[:])
	return signingInput + "." + enc.EncodeToString(sig)
}

func (p *oidcTestProvider) baseClaims() map[string]any {
	return map[string]any{
		"iss": p.issuer,
		"sub": "user-123",
		"aud": p.clientID,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Add(-time.Minute).Unix(),
	}
}

func (p *oidcTestProvider) newClient(t *testing.T) *oidcClient {
	t.Helper()
	c, err := newOIDCClient(context.Background(), runtimeConfig{
		Issuer:       p.issuer,
		ClientID:     p.clientID,
		ClientSecret: "client-secret",
		CallbackURL:  "https://app.test/callback",
		Scope:        "openid profile",
		Upstream:     newUpstreamHTTPClient(false),
	})
	if err != nil {
		t.Fatalf("newOIDCClient returned error: %v", err)
	}
	return c
}

func (p *oidcTestProvider) setToken(body string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tokenBody = body
}

func (p *oidcTestProvider) setJWKS(body string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.jwksBody = body
}

func (p *oidcTestProvider) jwksRequestCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.jwksRequests
}

func (p *oidcTestProvider) tokenRequestCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.tokenRequests
}

func (p *oidcTestProvider) capturedForm() url.Values {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.tokenForm
}

func computeAtHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

func hashForAlgorithm(t *testing.T, alg string) crypto.Hash {
	t.Helper()
	var h crypto.Hash
	switch alg {
	case "RS256", "PS256", "ES256":
		h = crypto.SHA256
	case "RS384", "PS384", "ES384":
		h = crypto.SHA384
	case "RS512", "PS512", "ES512", "EdDSA":
		h = crypto.SHA512
	default:
		t.Fatalf("unsupported test signing algorithm %q", alg)
	}
	return h
}

func computeAtHashForAlgorithm(t *testing.T, accessToken, alg string) string {
	t.Helper()
	h := hashForAlgorithm(t, alg).New()
	_, _ = h.Write([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:h.Size()/2])
}

func signIDTokenWithAlgorithm(t *testing.T, alg, kid string, key any, claims map[string]any) string {
	t.Helper()
	enc := base64.RawURLEncoding
	header := mustJSON(map[string]any{"alg": alg, "typ": "JWT", "kid": kid})
	payload := mustJSON(claims)
	signingInput := enc.EncodeToString([]byte(header)) + "." + enc.EncodeToString([]byte(payload))

	var sig []byte
	var err error
	switch alg {
	case "EdDSA":
		sig = ed25519.Sign(key.(ed25519.PrivateKey), []byte(signingInput))
	case "ES256", "ES384", "ES512":
		ecKey := key.(*ecdsa.PrivateKey)
		h := hashForAlgorithm(t, alg).New()
		_, _ = h.Write([]byte(signingInput))
		var r, s *big.Int
		r, s, err = ecdsa.Sign(rand.Reader, ecKey, h.Sum(nil))
		if err != nil {
			t.Fatalf("ecdsa.Sign returned error: %v", err)
		}
		size := (ecKey.Curve.Params().BitSize + 7) / 8
		sig = make([]byte, 2*size)
		r.FillBytes(sig[:size])
		s.FillBytes(sig[size:])
	default:
		rsaKey := key.(*rsa.PrivateKey)
		hash := hashForAlgorithm(t, alg)
		h := hash.New()
		_, _ = h.Write([]byte(signingInput))
		digest := h.Sum(nil)
		if alg[0:2] == "PS" {
			sig, err = rsa.SignPSS(rand.Reader, rsaKey, hash, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: hash})
		} else {
			sig, err = rsa.SignPKCS1v15(rand.Reader, rsaKey, hash, digest)
		}
	}
	if err != nil {
		t.Fatalf("signing ID token with %s returned error: %v", alg, err)
	}
	return signingInput + "." + enc.EncodeToString(sig)
}

func publicJWK(t *testing.T, alg, kid string, key any) map[string]any {
	t.Helper()
	jwk := map[string]any{"alg": alg, "kid": kid, "use": "sig"}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		jwk["kty"] = "RSA"
		jwk["n"] = base64.RawURLEncoding.EncodeToString(k.N.Bytes())
		jwk["e"] = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes())
	case *ecdsa.PrivateKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		x := make([]byte, size)
		y := make([]byte, size)
		k.X.FillBytes(x)
		k.Y.FillBytes(y)
		jwk["kty"] = "EC"
		jwk["crv"] = k.Curve.Params().Name
		jwk["x"] = base64.RawURLEncoding.EncodeToString(x)
		jwk["y"] = base64.RawURLEncoding.EncodeToString(y)
	case ed25519.PrivateKey:
		jwk["kty"] = "OKP"
		jwk["crv"] = "Ed25519"
		jwk["x"] = base64.RawURLEncoding.EncodeToString(k.Public().(ed25519.PublicKey))
	default:
		t.Fatalf("unsupported test key type %T", key)
	}
	return jwk
}

func marshalTokenResponse(access, refresh, idToken string, expiresIn int, refreshExp *int) string {
	resp := struct {
		AccessToken      string `json:"access_token"`
		RefreshToken     string `json:"refresh_token"`
		ExpiresIn        int    `json:"expires_in"`
		RefreshExpiresIn *int   `json:"refresh_expires_in,omitempty"`
		IDToken          string `json:"id_token,omitempty"`
	}{access, refresh, expiresIn, refreshExp, idToken}
	return mustJSON(resp)
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func intPtr(i int) *int { return &i }

func wantOIDCError(t *testing.T, err error, kind oidcErrKind) {
	t.Helper()
	var oe *oidcError
	if !errors.As(err, &oe) {
		t.Fatalf("error = %v, want *oidcError", err)
	}
	if oe.kind != kind {
		t.Fatalf("error kind = %v, want %v", oe.kind, kind)
	}
}

func TestNewOIDCClientDiscovery(t *testing.T) {
	p := newOIDCTestProvider(t)
	c, err := newOIDCClient(context.Background(), runtimeConfig{
		Issuer:       p.issuer,
		ClientID:     p.clientID,
		ClientSecret: "client-secret",
		CallbackURL:  "https://app.test/callback",
		Scope:        "openid",
		Upstream:     newUpstreamHTTPClient(false),
	})
	if err != nil {
		t.Fatalf("newOIDCClient returned error: %v", err)
	}
	if c.introspectionURL != p.issuer+"/protocol/openid-connect/token/introspect" {
		t.Fatalf("introspectionURL = %q, want %q", c.introspectionURL, p.issuer+"/protocol/openid-connect/token/introspect")
	}
}

func TestNewOIDCClientRejectsNoAsymmetricAlgorithm(t *testing.T) {
	p := newOIDCTestProvider(t)
	p.discoveryAlgorithms = []string{"HS256"}
	_, err := newOIDCClient(context.Background(), runtimeConfig{
		Issuer:       p.issuer,
		ClientID:     p.clientID,
		ClientSecret: "client-secret",
		CallbackURL:  "https://app.test/callback",
		Scope:        "openid",
		Upstream:     newUpstreamHTTPClient(false),
	})
	wantOIDCError(t, err, oidcErrMalformed)
}

func TestNewOIDCClientDiscoveryOutage(t *testing.T) {
	p := newOIDCTestProvider(t)
	p.discoveryStatus = http.StatusInternalServerError
	p.discoveryBody = `{"error":"SECRET_LEAK_MARKER"}`
	_, err := newOIDCClient(context.Background(), runtimeConfig{
		Issuer:       p.issuer,
		ClientID:     p.clientID,
		ClientSecret: "client-secret",
		CallbackURL:  "https://app.test/callback",
		Scope:        "openid",
		Upstream:     newUpstreamHTTPClient(false),
	})
	wantOIDCError(t, err, oidcErrOutage)
	for _, want := range []string{`path "/realms/r/.well-known/openid-configuration"`, "status 500"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want it to contain %q", err, want)
		}
	}
	for _, disallowed := range []string{p.srv.URL, "SECRET_LEAK_MARKER"} {
		if strings.Contains(err.Error(), disallowed) {
			t.Fatalf("error = %q, must not contain %q", err, disallowed)
		}
	}
}

func TestNewOIDCClientMalformedDiscovery(t *testing.T) {
	p := newOIDCTestProvider(t)
	p.discoveryBody = `{"not":"json"` + "\n" + `}`
	_, err := newOIDCClient(context.Background(), runtimeConfig{
		Issuer:       p.issuer,
		ClientID:     p.clientID,
		ClientSecret: "client-secret",
		CallbackURL:  "https://app.test/callback",
		Scope:        "openid",
		Upstream:     newUpstreamHTTPClient(false),
	})
	wantOIDCError(t, err, oidcErrMalformed)
}

func TestNewOIDCClientIssuerMismatch(t *testing.T) {
	p := newOIDCTestProvider(t)
	p.discoveryBody = mustJSON(map[string]any{
		"issuer":                 "https://evil.test/realms/r",
		"authorization_endpoint": p.issuer + "/protocol/openid-connect/auth",
		"token_endpoint":         p.issuer + "/protocol/openid-connect/token",
		"jwks_uri":               p.srv.URL + "/jwks",
	})
	_, err := newOIDCClient(context.Background(), runtimeConfig{
		Issuer:       p.issuer,
		ClientID:     p.clientID,
		ClientSecret: "client-secret",
		CallbackURL:  "https://app.test/callback",
		Scope:        "openid",
		Upstream:     newUpstreamHTTPClient(false),
	})
	wantOIDCError(t, err, oidcErrMalformed)
}

func TestNewOIDCClientRejectsInvalidProviderURLs(t *testing.T) {
	cases := []struct {
		name  string
		field string
		value string
	}{
		{"relative authorization endpoint", "authorization_endpoint", "/authorize"},
		{"non-HTTP authorization endpoint", "authorization_endpoint", "file:///authorize"},
		{"relative token endpoint", "token_endpoint", "/token"},
		{"non-HTTP token endpoint", "token_endpoint", "ftp://provider.test/token"},
		{"relative JWKS endpoint", "jwks_uri", "/jwks"},
		{"non-HTTP JWKS endpoint", "jwks_uri", "javascript:alert(1)"},
		{"endpoint without host", "jwks_uri", "https:///jwks"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newOIDCTestProvider(t)
			doc := map[string]any{
				"issuer":                 p.issuer,
				"authorization_endpoint": p.issuer + "/protocol/openid-connect/auth",
				"token_endpoint":         p.issuer + "/protocol/openid-connect/token",
				"jwks_uri":               p.srv.URL + "/jwks",
			}
			doc[tc.field] = tc.value
			p.discoveryBody = mustJSON(doc)

			_, err := newOIDCClient(context.Background(), runtimeConfig{
				Issuer:       p.issuer,
				ClientID:     p.clientID,
				ClientSecret: "client-secret",
				CallbackURL:  "https://app.test/callback",
				Scope:        "openid",
				Upstream:     newUpstreamHTTPClient(false),
			})
			wantOIDCError(t, err, oidcErrMalformed)
		})
	}
}

func TestNewOIDCClientDiscoveryExceedsLocalLimit(t *testing.T) {
	p := newOIDCTestProvider(t)
	// A discovery body over 1 MiB must be rejected even when the upstream
	// client does not bound the body itself, proving the local limit.
	p.discoveryBody = strings.Repeat("x", (1<<20)+1)
	_, err := newOIDCClient(context.Background(), runtimeConfig{
		Issuer:       p.issuer,
		ClientID:     p.clientID,
		ClientSecret: "client-secret",
		CallbackURL:  "https://app.test/callback",
		Scope:        "openid",
		Upstream:     &http.Client{},
	})
	wantOIDCError(t, err, oidcErrMalformed)
}

func TestNewOIDCClientDefaultsToRS256WhenAlgorithmsOmitted(t *testing.T) {
	p := newOIDCTestProvider(t)
	// Omit id_token_signing_alg_values_supported entirely; the OIDC default
	// RS256 must still be accepted.
	p.discoveryBody = mustJSON(map[string]any{
		"issuer":                 p.issuer,
		"authorization_endpoint": p.issuer + "/protocol/openid-connect/auth",
		"token_endpoint":         p.issuer + "/protocol/openid-connect/token",
		"introspection_endpoint": p.issuer + "/protocol/openid-connect/token/introspect",
		"jwks_uri":               p.srv.URL + "/jwks",
	})
	c := p.newClient(t)

	access := "access-token"
	claims := p.baseClaims()
	claims["nonce"] = "n0nce"
	claims["at_hash"] = computeAtHash(access)
	p.setToken(marshalTokenResponse(access, "refresh", p.signIDToken(claims), 300, nil))

	ts, err := c.exchange(context.Background(), "code", "verifier", "n0nce")
	if err != nil {
		t.Fatalf("exchange returned error: %v", err)
	}
	if ts.Identity.Subject != "user-123" {
		t.Fatalf("Identity.Subject = %q, want user-123", ts.Identity.Subject)
	}
}

func TestAuthCodeURLContainsExactCallbackS256AndNonce(t *testing.T) {
	p := newOIDCTestProvider(t)
	c := p.newClient(t)

	raw := c.authCodeURL("st4te", "n0nce", "ch4llenge")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("authCodeURL returned unparseable URL %q: %v", raw, err)
	}
	q := u.Query()
	if got := q.Get("response_type"); got != "code" {
		t.Fatalf("response_type = %q, want code", got)
	}
	if got := q.Get("client_id"); got != p.clientID {
		t.Fatalf("client_id = %q, want %q", got, p.clientID)
	}
	if got := q.Get("redirect_uri"); got != "https://app.test/callback" {
		t.Fatalf("redirect_uri = %q, want exact callback", got)
	}
	if got := q.Get("scope"); !strings.Contains(got, "openid") {
		t.Fatalf("scope = %q, want openid included", got)
	}
	if got := q.Get("state"); got != "st4te" {
		t.Fatalf("state = %q, want st4te", got)
	}
	if got := q.Get("nonce"); got != "n0nce" {
		t.Fatalf("nonce = %q, want n0nce", got)
	}
	if got := q.Get("code_challenge"); got != "ch4llenge" {
		t.Fatalf("code_challenge = %q, want ch4llenge", got)
	}
	if got := q.Get("code_challenge_method"); got != "S256" {
		t.Fatalf("code_challenge_method = %q, want S256", got)
	}
}

func TestExchangeValidIDToken(t *testing.T) {
	p := newOIDCTestProvider(t)
	c := p.newClient(t)

	access := "access-token"
	claims := p.baseClaims()
	claims["nonce"] = "n0nce"
	claims["at_hash"] = computeAtHash(access)
	claims["preferred_username"] = "alice"
	idToken := p.signIDToken(claims)
	p.setToken(marshalTokenResponse(access, "refresh-token", idToken, 300, intPtr(1800)))

	ts, err := c.exchange(context.Background(), "code", "verifier", "n0nce")
	if err != nil {
		t.Fatalf("exchange returned error: %v", err)
	}
	if ts.AccessToken != access {
		t.Fatalf("AccessToken = %q, want %q", ts.AccessToken, access)
	}
	if ts.RefreshToken != "refresh-token" {
		t.Fatalf("RefreshToken = %q, want refresh-token", ts.RefreshToken)
	}
	if ts.ExpiresIn != 300 {
		t.Fatalf("ExpiresIn = %d, want 300", ts.ExpiresIn)
	}
	if ts.RefreshExpiresIn == nil || *ts.RefreshExpiresIn != 1800 {
		t.Fatalf("RefreshExpiresIn = %v, want 1800", ts.RefreshExpiresIn)
	}
	if ts.Identity.Subject != "user-123" {
		t.Fatalf("Identity.Subject = %q, want user-123", ts.Identity.Subject)
	}
	if got := ts.Identity.Claims["preferred_username"]; got != "alice" {
		t.Fatalf("preferred_username = %v, want alice", got)
	}
}

func TestExchangeSupportsAsymmetricAlgorithms(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey returned error: %v", err)
	}
	cases := []struct {
		alg    string
		newKey func(*testing.T) any
	}{
		{"RS256", func(*testing.T) any { return rsaKey }},
		{"RS384", func(*testing.T) any { return rsaKey }},
		{"RS512", func(*testing.T) any { return rsaKey }},
		{"PS256", func(*testing.T) any { return rsaKey }},
		{"PS384", func(*testing.T) any { return rsaKey }},
		{"PS512", func(*testing.T) any { return rsaKey }},
		{"ES256", func(t *testing.T) any {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("ecdsa.GenerateKey returned error: %v", err)
			}
			return key
		}},
		{"ES384", func(t *testing.T) any {
			key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			if err != nil {
				t.Fatalf("ecdsa.GenerateKey returned error: %v", err)
			}
			return key
		}},
		{"ES512", func(t *testing.T) any {
			key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
			if err != nil {
				t.Fatalf("ecdsa.GenerateKey returned error: %v", err)
			}
			return key
		}},
		{"EdDSA", func(t *testing.T) any {
			_, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("ed25519.GenerateKey returned error: %v", err)
			}
			return key
		}},
	}
	for _, tc := range cases {
		t.Run(tc.alg, func(t *testing.T) {
			p := newOIDCTestProvider(t)
			p.discoveryAlgorithms = []string{tc.alg}
			key := tc.newKey(t)
			p.setJWKS(mustJSON(map[string]any{"keys": []any{publicJWK(t, tc.alg, p.kid, key)}}))
			c := p.newClient(t)

			access := "access-token"
			claims := p.baseClaims()
			claims["nonce"] = "n0nce"
			claims["at_hash"] = computeAtHashForAlgorithm(t, access, tc.alg)
			idToken := signIDTokenWithAlgorithm(t, tc.alg, p.kid, key, claims)
			p.setToken(marshalTokenResponse(access, "refresh", idToken, 300, nil))

			ts, err := c.exchange(context.Background(), "code", "verifier", "n0nce")
			if err != nil {
				t.Fatalf("exchange returned error for %s: %v", tc.alg, err)
			}
			if ts.Identity.Subject != "user-123" {
				t.Fatalf("Identity.Subject = %q, want user-123", ts.Identity.Subject)
			}
		})
	}
}

func TestECDSAPublicKeyRejectsOffCurvePoint(t *testing.T) {
	coordinate := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	key := jwkJSON{KeyType: "EC", Curve: "P-256", X: coordinate, Y: coordinate}

	_, err := key.ecdsaPublicKey()
	if err == nil {
		t.Fatal("ecdsaPublicKey accepted an off-curve point")
	}
	if got, want := err.Error(), "oidc: invalid ECDSA jwks key"; got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
}

func TestExchangeSendsS256VerifierAndExactRedirect(t *testing.T) {
	p := newOIDCTestProvider(t)
	c := p.newClient(t)

	access := "access-token"
	claims := p.baseClaims()
	claims["nonce"] = "n0nce"
	claims["at_hash"] = computeAtHash(access)
	p.setToken(marshalTokenResponse(access, "refresh-token", p.signIDToken(claims), 300, nil))

	if _, err := c.exchange(context.Background(), "code", "the-verifier", "n0nce"); err != nil {
		t.Fatalf("exchange returned error: %v", err)
	}
	form := p.capturedForm()
	if got := form.Get("grant_type"); got != "authorization_code" {
		t.Fatalf("grant_type = %q, want authorization_code", got)
	}
	if got := form.Get("code"); got != "code" {
		t.Fatalf("code = %q, want code", got)
	}
	if got := form.Get("code_verifier"); got != "the-verifier" {
		t.Fatalf("code_verifier = %q, want the-verifier", got)
	}
	if got := form.Get("redirect_uri"); got != "https://app.test/callback" {
		t.Fatalf("redirect_uri = %q, want exact callback", got)
	}
	if got := form.Get("client_id"); got != p.clientID {
		t.Fatalf("client_id = %q, want %q", got, p.clientID)
	}
	if got := form.Get("client_secret"); got != "client-secret" {
		t.Fatalf("client_secret = %q, want client-secret", got)
	}
}

func TestExchangeRejectsNoneAlgorithm(t *testing.T) {
	p := newOIDCTestProvider(t)
	c := p.newClient(t)

	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"none"}`))
	payload := enc.EncodeToString([]byte(mustJSON(p.baseClaims())))
	p.setToken(marshalTokenResponse("access", "refresh", header+"."+payload+".", 300, nil))

	_, err := c.exchange(context.Background(), "code", "verifier", "n0nce")
	wantOIDCError(t, err, oidcErrMalformed)
}

func TestExchangeRejectsHMACAlgorithm(t *testing.T) {
	p := newOIDCTestProvider(t)
	c := p.newClient(t)

	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := enc.EncodeToString([]byte(mustJSON(p.baseClaims())))
	signingInput := header + "." + payload
	mac := hmac.New(sha256.New, []byte("shared-secret"))
	mac.Write([]byte(signingInput))
	sig := enc.EncodeToString(mac.Sum(nil))
	p.setToken(marshalTokenResponse("access", "refresh", signingInput+"."+sig, 300, nil))

	_, err := c.exchange(context.Background(), "code", "verifier", "n0nce")
	wantOIDCError(t, err, oidcErrMalformed)
}

func TestExchangeRejectsBadSignature(t *testing.T) {
	p := newOIDCTestProvider(t)
	c := p.newClient(t)

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey returned error: %v", err)
	}
	enc := base64.RawURLEncoding
	header := `{"alg":"RS256","typ":"JWT","kid":"` + p.kid + `"}`
	payload, _ := json.Marshal(p.baseClaims())
	signingInput := enc.EncodeToString([]byte(header)) + "." + enc.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, otherKey, crypto.SHA256, digest[:])
	p.setToken(marshalTokenResponse("access", "refresh", signingInput+"."+enc.EncodeToString(sig), 300, nil))

	_, err = c.exchange(context.Background(), "code", "verifier", "n0nce")
	wantOIDCError(t, err, oidcErrMalformed)
}

func TestExchangeRejectsWrongIssuer(t *testing.T) {
	p := newOIDCTestProvider(t)
	c := p.newClient(t)

	claims := p.baseClaims()
	claims["iss"] = "https://evil.test/realms/r"
	claims["nonce"] = "n0nce"
	p.setToken(marshalTokenResponse("access", "refresh", p.signIDToken(claims), 300, nil))

	_, err := c.exchange(context.Background(), "code", "verifier", "n0nce")
	wantOIDCError(t, err, oidcErrMalformed)
}

func TestExchangeRejectsWrongAudience(t *testing.T) {
	p := newOIDCTestProvider(t)
	c := p.newClient(t)

	claims := p.baseClaims()
	claims["aud"] = "other-client"
	claims["nonce"] = "n0nce"
	p.setToken(marshalTokenResponse("access", "refresh", p.signIDToken(claims), 300, nil))

	_, err := c.exchange(context.Background(), "code", "verifier", "n0nce")
	wantOIDCError(t, err, oidcErrMalformed)
}

func TestExchangeRejectsMultipleAudienceWithoutAuthorizedParty(t *testing.T) {
	p := newOIDCTestProvider(t)
	c := p.newClient(t)

	claims := p.baseClaims()
	claims["aud"] = []string{p.clientID, "other-client"}
	claims["nonce"] = "n0nce"
	p.setToken(marshalTokenResponse("access", "refresh", p.signIDToken(claims), 300, nil))

	_, err := c.exchange(context.Background(), "code", "verifier", "n0nce")
	wantOIDCError(t, err, oidcErrMalformed)
}

func TestExchangeAcceptsMultipleAudienceWithValidAuthorizedParty(t *testing.T) {
	p := newOIDCTestProvider(t)
	c := p.newClient(t)

	access := "access-token"
	claims := p.baseClaims()
	claims["aud"] = []string{p.clientID, "other-client"}
	claims["azp"] = p.clientID
	claims["nonce"] = "n0nce"
	claims["at_hash"] = computeAtHash(access)
	p.setToken(marshalTokenResponse(access, "refresh", p.signIDToken(claims), 300, nil))

	ts, err := c.exchange(context.Background(), "code", "verifier", "n0nce")
	if err != nil {
		t.Fatalf("exchange returned error: %v", err)
	}
	if ts.Identity.Subject != "user-123" {
		t.Fatalf("Identity.Subject = %q, want user-123", ts.Identity.Subject)
	}
}

func TestExchangeRejectsInvalidAuthorizedParty(t *testing.T) {
	cases := []struct {
		name string
		aud  any
		azp  any
	}{
		{"single audience mismatch", "client-id", "other-client"},
		{"single audience non-string", "client-id", 123},
		{"multiple audiences mismatch", []string{"client-id", "other-audience"}, "other-client"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newOIDCTestProvider(t)
			c := p.newClient(t)

			claims := p.baseClaims()
			claims["aud"] = tc.aud
			claims["azp"] = tc.azp
			claims["nonce"] = "n0nce"
			p.setToken(marshalTokenResponse("access", "refresh", p.signIDToken(claims), 300, nil))

			_, err := c.exchange(context.Background(), "code", "verifier", "n0nce")
			wantOIDCError(t, err, oidcErrMalformed)
		})
	}
}

func TestExchangeRejectsExpiredIDToken(t *testing.T) {
	p := newOIDCTestProvider(t)
	c := p.newClient(t)

	claims := p.baseClaims()
	claims["exp"] = time.Now().Add(-time.Hour).Unix()
	claims["nonce"] = "n0nce"
	p.setToken(marshalTokenResponse("access", "refresh", p.signIDToken(claims), 300, nil))

	_, err := c.exchange(context.Background(), "code", "verifier", "n0nce")
	wantOIDCError(t, err, oidcErrMalformed)
}

func TestExchangeRejectsMissingSubject(t *testing.T) {
	p := newOIDCTestProvider(t)
	c := p.newClient(t)

	claims := p.baseClaims()
	delete(claims, "sub")
	claims["nonce"] = "n0nce"
	p.setToken(marshalTokenResponse("access", "refresh", p.signIDToken(claims), 300, nil))

	_, err := c.exchange(context.Background(), "code", "verifier", "n0nce")
	wantOIDCError(t, err, oidcErrMalformed)
}

func TestExchangeRejectsInvalidTimeClaims(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"missing expiry", func(claims map[string]any) { delete(claims, "exp") }},
		{"missing issued at", func(claims map[string]any) { delete(claims, "iat") }},
		{"invalid issued at", func(claims map[string]any) { claims["iat"] = "not-a-number" }},
		{"not before beyond skew", func(claims map[string]any) {
			claims["nbf"] = time.Now().Add(2 * time.Minute).Unix()
		}},
		{"issued at beyond skew", func(claims map[string]any) {
			claims["iat"] = time.Now().Add(2 * time.Minute).Unix()
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newOIDCTestProvider(t)
			c := p.newClient(t)

			claims := p.baseClaims()
			claims["nonce"] = "n0nce"
			tc.mutate(claims)
			p.setToken(marshalTokenResponse("access", "refresh", p.signIDToken(claims), 300, nil))

			_, err := c.exchange(context.Background(), "code", "verifier", "n0nce")
			wantOIDCError(t, err, oidcErrMalformed)
		})
	}
}

func TestExchangeAcceptsTimeClaimsWithinSkew(t *testing.T) {
	p := newOIDCTestProvider(t)
	c := p.newClient(t)

	claims := p.baseClaims()
	claims["exp"] = time.Now().Add(-30 * time.Second).Unix()
	claims["nbf"] = time.Now().Add(30 * time.Second).Unix()
	claims["iat"] = time.Now().Add(30 * time.Second).Unix()
	claims["nonce"] = "n0nce"
	p.setToken(marshalTokenResponse("access", "refresh", p.signIDToken(claims), 300, nil))

	if _, err := c.exchange(context.Background(), "code", "verifier", "n0nce"); err != nil {
		t.Fatalf("exchange returned error for claims within 60-second skew: %v", err)
	}
}

func TestExchangeRejectsNonceMismatch(t *testing.T) {
	p := newOIDCTestProvider(t)
	c := p.newClient(t)

	claims := p.baseClaims()
	claims["nonce"] = "different-nonce"
	p.setToken(marshalTokenResponse("access", "refresh", p.signIDToken(claims), 300, nil))

	_, err := c.exchange(context.Background(), "code", "verifier", "expected-nonce")
	wantOIDCError(t, err, oidcErrMalformed)
}

func TestExchangeRejectsBadAtHash(t *testing.T) {
	p := newOIDCTestProvider(t)
	c := p.newClient(t)

	claims := p.baseClaims()
	claims["nonce"] = "n0nce"
	claims["at_hash"] = computeAtHash("some-other-access-token")
	p.setToken(marshalTokenResponse("access-token", "refresh", p.signIDToken(claims), 300, nil))

	_, err := c.exchange(context.Background(), "code", "verifier", "n0nce")
	wantOIDCError(t, err, oidcErrMalformed)
}

func TestExchangeRejectsEmptyAtHash(t *testing.T) {
	p := newOIDCTestProvider(t)
	c := p.newClient(t)

	claims := p.baseClaims()
	claims["nonce"] = "n0nce"
	claims["at_hash"] = ""
	p.setToken(marshalTokenResponse("access-token", "refresh", p.signIDToken(claims), 300, nil))

	_, err := c.exchange(context.Background(), "code", "verifier", "n0nce")
	wantOIDCError(t, err, oidcErrMalformed)
}

func TestExchangeRejectsMissingIDToken(t *testing.T) {
	p := newOIDCTestProvider(t)
	c := p.newClient(t)

	p.setToken(marshalTokenResponse("access-token", "refresh-token", "", 300, nil))

	_, err := c.exchange(context.Background(), "code", "verifier", "n0nce")
	wantOIDCError(t, err, oidcErrMalformed)
}

func TestExchangeRejectsMissingRefreshToken(t *testing.T) {
	p := newOIDCTestProvider(t)
	c := p.newClient(t)

	claims := p.baseClaims()
	claims["nonce"] = "n0nce"
	p.setToken(marshalTokenResponse("access-token", "", p.signIDToken(claims), 300, nil))

	_, err := c.exchange(context.Background(), "code", "verifier", "n0nce")
	wantOIDCError(t, err, oidcErrMalformed)
}

func TestExchangeRejectsMissingAccessToken(t *testing.T) {
	p := newOIDCTestProvider(t)
	c := p.newClient(t)

	claims := p.baseClaims()
	claims["nonce"] = "n0nce"
	p.setToken(marshalTokenResponse("", "refresh-token", p.signIDToken(claims), 300, nil))

	_, err := c.exchange(context.Background(), "code", "verifier", "n0nce")
	wantOIDCError(t, err, oidcErrMalformed)
}

func TestExchangeRejectsMalformedIDToken(t *testing.T) {
	p := newOIDCTestProvider(t)
	c := p.newClient(t)

	p.setToken(marshalTokenResponse("access-token", "refresh-token", "not-a-jwt", 300, nil))

	_, err := c.exchange(context.Background(), "code", "verifier", "n0nce")
	wantOIDCError(t, err, oidcErrMalformed)
}

func TestExchangeCachesJWKS(t *testing.T) {
	p := newOIDCTestProvider(t)
	c := p.newClient(t)
	claims := p.baseClaims()
	claims["nonce"] = "n0nce"
	p.setToken(marshalTokenResponse("access", "refresh", p.signIDToken(claims), 300, nil))

	for i := 0; i < 2; i++ {
		if _, err := c.exchange(context.Background(), "code", "verifier", "n0nce"); err != nil {
			t.Fatalf("exchange %d returned error: %v", i+1, err)
		}
	}
	if got := p.jwksRequestCount(); got != 1 {
		t.Fatalf("JWKS requests = %d, want 1", got)
	}
}

func TestExchangeRefetchesJWKSOnceForUnknownKid(t *testing.T) {
	p := newOIDCTestProvider(t)
	c := p.newClient(t)
	claims := p.baseClaims()
	claims["nonce"] = "n0nce"
	p.setToken(marshalTokenResponse("access", "refresh", p.signIDToken(claims), 300, nil))
	if _, err := c.exchange(context.Background(), "code", "verifier", "n0nce"); err != nil {
		t.Fatalf("initial exchange returned error: %v", err)
	}

	unknownKeyToken := signIDTokenWithAlgorithm(t, "RS256", "unknown-key", p.key, claims)
	p.setToken(marshalTokenResponse("access", "refresh", unknownKeyToken, 300, nil))
	_, err := c.exchange(context.Background(), "code", "verifier", "n0nce")
	wantOIDCError(t, err, oidcErrMalformed)
	if got := p.jwksRequestCount(); got != 2 {
		t.Fatalf("JWKS requests = %d, want initial fetch and one refetch", got)
	}
}

func TestExchangeConcurrentCachedJWKS(t *testing.T) {
	p := newOIDCTestProvider(t)
	c := p.newClient(t)
	claims := p.baseClaims()
	claims["nonce"] = "n0nce"
	p.setToken(marshalTokenResponse("access", "refresh", p.signIDToken(claims), 300, nil))
	if _, err := c.exchange(context.Background(), "code", "verifier", "n0nce"); err != nil {
		t.Fatalf("initial exchange returned error: %v", err)
	}

	const exchanges = 8
	var wg sync.WaitGroup
	errs := make(chan error, exchanges)
	for i := 0; i < exchanges; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := c.exchange(context.Background(), "code", "verifier", "n0nce")
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent exchange returned error: %v", err)
		}
	}
	if got := p.jwksRequestCount(); got != 1 {
		t.Fatalf("JWKS requests = %d, want 1", got)
	}
}

func TestExchangeRejectsUnsupportedProviderAlgorithm(t *testing.T) {
	p := newOIDCTestProvider(t)
	// The provider advertises only RS256, so an RS512-signed token must be
	// rejected even though RS512 is a valid asymmetric algorithm.
	p.discoveryAlgorithms = []string{"RS256"}
	c := p.newClient(t)

	enc := base64.RawURLEncoding
	header := `{"alg":"RS512","typ":"JWT","kid":"` + p.kid + `"}`
	payload, _ := json.Marshal(p.baseClaims())
	signingInput := enc.EncodeToString([]byte(header)) + "." + enc.EncodeToString(payload)
	digest := sha512Sum(signingInput)
	sig, _ := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA512, digest)
	p.setToken(marshalTokenResponse("access", "refresh", signingInput+"."+enc.EncodeToString(sig), 300, nil))

	_, err := c.exchange(context.Background(), "code", "verifier", "n0nce")
	wantOIDCError(t, err, oidcErrMalformed)
}

func sha512Sum(s string) []byte {
	h := sha512.New()
	h.Write([]byte(s))
	return h.Sum(nil)
}

func TestRefreshRotatesTokensAndValidatesIDToken(t *testing.T) {
	p := newOIDCTestProvider(t)
	c := p.newClient(t)

	access := "new-access-token"
	claims := p.baseClaims()
	claims["at_hash"] = computeAtHash(access)
	idToken := p.signIDToken(claims)
	p.setToken(marshalTokenResponse(access, "new-refresh-token", idToken, 300, intPtr(1800)))

	ts, err := c.refresh(context.Background(), "old-refresh-token")
	if err != nil {
		t.Fatalf("refresh returned error: %v", err)
	}
	if ts.AccessToken != access {
		t.Fatalf("AccessToken = %q, want %q", ts.AccessToken, access)
	}
	if ts.RefreshToken != "new-refresh-token" {
		t.Fatalf("RefreshToken = %q, want new-refresh-token (rotated)", ts.RefreshToken)
	}
	if ts.Identity.Subject != "user-123" {
		t.Fatalf("Identity.Subject = %q, want user-123 (subject preserved)", ts.Identity.Subject)
	}
	if ts.RefreshExpiresIn == nil || *ts.RefreshExpiresIn != 1800 {
		t.Fatalf("RefreshExpiresIn = %v, want 1800", ts.RefreshExpiresIn)
	}

	form := p.capturedForm()
	if got := form.Get("grant_type"); got != "refresh_token" {
		t.Fatalf("grant_type = %q, want refresh_token", got)
	}
	if got := form.Get("refresh_token"); got != "old-refresh-token" {
		t.Fatalf("refresh_token = %q, want old-refresh-token", got)
	}
}

func TestRefreshMissingIDTokenPreservesIdentity(t *testing.T) {
	p := newOIDCTestProvider(t)
	c := p.newClient(t)

	p.setToken(marshalTokenResponse("new-access-token", "new-refresh-token", "", 300, nil))

	ts, err := c.refresh(context.Background(), "old-refresh-token")
	if err != nil {
		t.Fatalf("refresh returned error: %v", err)
	}
	if ts.Identity.Subject != "" || ts.Identity.Claims != nil {
		t.Fatalf("Identity = %+v, want zero identity when refreshed id token is absent", ts.Identity)
	}
}

func TestRefreshKeepsRefreshTokenWhenNotRotated(t *testing.T) {
	p := newOIDCTestProvider(t)
	c := p.newClient(t)

	p.setToken(marshalTokenResponse("new-access-token", "", "", 300, nil))

	ts, err := c.refresh(context.Background(), "old-refresh-token")
	if err != nil {
		t.Fatalf("refresh returned error: %v", err)
	}
	if ts.RefreshToken != "old-refresh-token" {
		t.Fatalf("RefreshToken = %q, want old-refresh-token retained", ts.RefreshToken)
	}
}

func TestRefreshRejectsNonStringIDToken(t *testing.T) {
	p := newOIDCTestProvider(t)
	c := p.newClient(t)
	p.setToken(mustJSON(map[string]any{
		"access_token":  "access",
		"refresh_token": "refresh",
		"expires_in":    300,
		"id_token":      123,
	}))

	_, err := c.refresh(context.Background(), "old-refresh-token")
	wantOIDCError(t, err, oidcErrMalformed)
}

func TestRefreshRejectsBadIDTokenSignature(t *testing.T) {
	p := newOIDCTestProvider(t)
	c := p.newClient(t)

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey returned error: %v", err)
	}
	enc := base64.RawURLEncoding
	header := `{"alg":"RS256","typ":"JWT","kid":"` + p.kid + `"}`
	payload, _ := json.Marshal(p.baseClaims())
	signingInput := enc.EncodeToString([]byte(header)) + "." + enc.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, otherKey, crypto.SHA256, digest[:])
	p.setToken(marshalTokenResponse("access", "refresh", signingInput+"."+enc.EncodeToString(sig), 300, nil))

	_, err = c.refresh(context.Background(), "old-refresh-token")
	wantOIDCError(t, err, oidcErrMalformed)
}

func TestRefreshRequiresValidIssuedAt(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"missing", func(claims map[string]any) { delete(claims, "iat") }},
		{"invalid", func(claims map[string]any) { claims["iat"] = "not-a-number" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newOIDCTestProvider(t)
			c := p.newClient(t)
			claims := p.baseClaims()
			tc.mutate(claims)
			p.setToken(marshalTokenResponse("access", "refresh", p.signIDToken(claims), 300, nil))

			_, err := c.refresh(context.Background(), "old-refresh-token")
			wantOIDCError(t, err, oidcErrMalformed)
		})
	}
}

func TestTokenFlowsRequirePositiveExpiresIn(t *testing.T) {
	lifetimes := []struct {
		name  string
		value int
		omit  bool
	}{
		{"omitted", 0, true},
		{"zero", 0, false},
		{"negative", -1, false},
	}
	for _, flow := range []string{"exchange", "refresh"} {
		for _, lifetime := range lifetimes {
			t.Run(flow+"/"+lifetime.name, func(t *testing.T) {
				p := newOIDCTestProvider(t)
				c := p.newClient(t)
				response := map[string]any{
					"access_token":  "access",
					"refresh_token": "refresh",
				}
				if !lifetime.omit {
					response["expires_in"] = lifetime.value
				}
				if flow == "exchange" {
					claims := p.baseClaims()
					claims["nonce"] = "n0nce"
					response["id_token"] = p.signIDToken(claims)
				}
				p.setToken(mustJSON(response))

				var err error
				if flow == "exchange" {
					_, err = c.exchange(context.Background(), "code", "verifier", "n0nce")
				} else {
					_, err = c.refresh(context.Background(), "old-refresh-token")
				}
				wantOIDCError(t, err, oidcErrMalformed)
			})
		}
	}
}

func TestTokenFlowsAcceptFormEncodedExpiresIn(t *testing.T) {
	for _, flow := range []string{"exchange", "refresh"} {
		t.Run(flow, func(t *testing.T) {
			p := newOIDCTestProvider(t)
			c := p.newClient(t)
			response := url.Values{
				"access_token":  {"access"},
				"refresh_token": {"refresh"},
				"expires_in":    {"300"},
			}
			if flow == "exchange" {
				claims := p.baseClaims()
				claims["nonce"] = "n0nce"
				response.Set("id_token", p.signIDToken(claims))
			}
			p.tokenContentType = "application/x-www-form-urlencoded"
			p.setToken(response.Encode())

			var ts *tokenSet
			var err error
			if flow == "exchange" {
				ts, err = c.exchange(context.Background(), "code", "verifier", "n0nce")
			} else {
				ts, err = c.refresh(context.Background(), "old-refresh-token")
			}
			if err != nil {
				t.Fatalf("%s returned error: %v", flow, err)
			}
			if ts.ExpiresIn != 300 {
				t.Fatalf("ExpiresIn = %d, want 300", ts.ExpiresIn)
			}
		})
	}
}

func TestRefreshExpirySemantics(t *testing.T) {
	cases := []struct {
		name     string
		refresh  *int
		wantNil  bool
		wantZero bool
		wantVal  int
	}{
		{"omitted", nil, true, false, 0},
		{"zero", intPtr(0), false, true, 0},
		{"positive", intPtr(1800), false, false, 1800},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newOIDCTestProvider(t)
			c := p.newClient(t)
			p.setToken(marshalTokenResponse("access", "refresh", "", 300, tc.refresh))

			ts, err := c.refresh(context.Background(), "old-refresh-token")
			if err != nil {
				t.Fatalf("refresh returned error: %v", err)
			}
			switch {
			case tc.wantNil:
				if ts.RefreshExpiresIn != nil {
					t.Fatalf("RefreshExpiresIn = %v, want nil", ts.RefreshExpiresIn)
				}
			case tc.wantZero:
				if ts.RefreshExpiresIn == nil || *ts.RefreshExpiresIn != 0 {
					t.Fatalf("RefreshExpiresIn = %v, want 0", ts.RefreshExpiresIn)
				}
			default:
				if ts.RefreshExpiresIn == nil || *ts.RefreshExpiresIn != tc.wantVal {
					t.Fatalf("RefreshExpiresIn = %v, want %d", ts.RefreshExpiresIn, tc.wantVal)
				}
			}
		})
	}
}

func TestRefreshExpiryNegativeRejected(t *testing.T) {
	p := newOIDCTestProvider(t)
	c := p.newClient(t)
	p.setToken(marshalTokenResponse("access", "refresh", "", 300, intPtr(-1)))

	_, err := c.refresh(context.Background(), "old-refresh-token")
	wantOIDCError(t, err, oidcErrMalformed)
}

func TestRefreshRefusalClassifiedWithoutBodyLeak(t *testing.T) {
	p := newOIDCTestProvider(t)
	c := p.newClient(t)
	p.tokenStatus = http.StatusBadRequest
	p.setToken(`{"error":"invalid_grant","error_description":"SECRET_LEAK_MARKER"}`)

	_, err := c.refresh(context.Background(), "old-refresh-token")
	wantOIDCError(t, err, oidcErrRefusal)
	if strings.Contains(err.Error(), "SECRET_LEAK_MARKER") {
		t.Fatalf("error leaked upstream body: %v", err)
	}
}

func TestRefreshNonInvalidGrantErrorsAreNotRefusals(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"invalid client", http.StatusUnauthorized, `{"error":"invalid_client"}`},
		{"invalid request", http.StatusBadRequest, `{"error":"invalid_request"}`},
		{"bodyless bad request", http.StatusBadRequest, ""},
		{"malformed bad request", http.StatusBadRequest, "not json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newOIDCTestProvider(t)
			c := p.newClient(t)
			p.tokenStatus = tc.status
			p.setToken(tc.body)

			_, err := c.refresh(context.Background(), "old-refresh-token")
			wantOIDCError(t, err, oidcErrMalformed)
			if isOIDCRefusal(err) {
				t.Fatal("only invalid_grant may be classified as a refusal")
			}
		})
	}
}

func TestRefreshOutageClassified(t *testing.T) {
	p := newOIDCTestProvider(t)
	c := p.newClient(t)
	p.tokenStatus = http.StatusInternalServerError
	p.setToken(`{"error":"temporarily_unavailable"}`)

	_, err := c.refresh(context.Background(), "old-refresh-token")
	wantOIDCError(t, err, oidcErrOutage)
	if strings.Contains(err.Error(), "temporarily_unavailable") {
		t.Fatalf("error leaked upstream body: %v", err)
	}
}

func TestRefreshMalformedClassified(t *testing.T) {
	p := newOIDCTestProvider(t)
	c := p.newClient(t)
	p.tokenStatus = http.StatusOK
	p.setToken(`this is not json`)

	_, err := c.refresh(context.Background(), "old-refresh-token")
	wantOIDCError(t, err, oidcErrMalformed)
}

func TestIntrospectStatuses(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		want    tokenStatus
		wantErr oidcErrKind
	}{
		{"active", http.StatusOK, `{"active":true}`, tokenActive, -1},
		{"inactive", http.StatusOK, `{"active":false}`, tokenInactive, -1},
		{"refusal", http.StatusUnauthorized, `{"error":"invalid_client"}`, tokenUnavailable, oidcErrRefusal},
		{"outage", http.StatusInternalServerError, `oops`, tokenUnavailable, oidcErrOutage},
		{"malformed", http.StatusOK, `not json`, tokenUnavailable, oidcErrMalformed},
		{"multiple objects", http.StatusOK, `{"active":true}{"active":false}`, tokenUnavailable, oidcErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newOIDCTestProvider(t)
			c := p.newClient(t)
			p.introspectStatus = tc.status
			p.introspectBody = tc.body

			status, err := c.introspect(context.Background(), "access-token")
			if status != tc.want {
				t.Fatalf("status = %v, want %v", status, tc.want)
			}
			if tc.wantErr == -1 {
				if err != nil {
					t.Fatalf("introspect returned unexpected error: %v", err)
				}
				return
			}
			wantOIDCError(t, err, tc.wantErr)
		})
	}
}

func TestIntrospectRefusalDoesNotLeakBody(t *testing.T) {
	p := newOIDCTestProvider(t)
	c := p.newClient(t)
	p.introspectStatus = http.StatusUnauthorized
	p.introspectBody = `{"error":"invalid_client","error_description":"SECRET_LEAK_MARKER"}`

	_, err := c.introspect(context.Background(), "access-token")
	wantOIDCError(t, err, oidcErrRefusal)
	if strings.Contains(err.Error(), "SECRET_LEAK_MARKER") {
		t.Fatalf("error leaked upstream body: %v", err)
	}
}

func TestSanitizeOAuthErrPropagatesContextErrors(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want error
	}{
		{"canceled", context.Canceled, context.Canceled},
		{"deadline exceeded", context.DeadlineExceeded, context.DeadlineExceeded},
		{"wrapped canceled", fmt.Errorf("token request: %w", context.Canceled), context.Canceled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeOAuthErr(tc.err)
			if !errors.Is(got, tc.want) {
				t.Fatalf("sanitizeOAuthErr(%v) = %v, want errors.Is to match %v", tc.err, got, tc.want)
			}
		})
	}
}
