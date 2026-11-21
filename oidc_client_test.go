package keycloakopenid

import (
	"context"
	"crypto"
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

	tokenStatus int
	tokenBody   string
	tokenForm   url.Values

	introspectStatus int
	introspectBody   string
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
	n := base64.RawURLEncoding.EncodeToString(p.key.PublicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.key.PublicKey.E)).Bytes())
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(rw, `{"keys":[{"kty":"RSA","kid":%q,"alg":"RS256","use":"sig","n":%q,"e":%q}]}`, p.kid, n, e)
}

func (p *oidcTestProvider) serveToken(rw http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	p.tokenForm = req.PostForm
	status := p.tokenStatus
	body := p.tokenBody
	p.mu.Unlock()

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	_, _ = rw.Write([]byte(body))
}

func (p *oidcTestProvider) serveIntrospect(rw http.ResponseWriter) {
	p.mu.Lock()
	status := p.introspectStatus
	body := p.introspectBody
	p.mu.Unlock()
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

func (p *oidcTestProvider) capturedForm() url.Values {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.tokenForm
}

func computeAtHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
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
	_, err := newOIDCClient(context.Background(), runtimeConfig{
		Issuer:       p.issuer,
		ClientID:     p.clientID,
		ClientSecret: "client-secret",
		CallbackURL:  "https://app.test/callback",
		Scope:        "openid",
		Upstream:     newUpstreamHTTPClient(false),
	})
	wantOIDCError(t, err, oidcErrOutage)
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

func TestExchangeRejectsMalformedIDToken(t *testing.T) {
	p := newOIDCTestProvider(t)
	c := p.newClient(t)

	p.setToken(marshalTokenResponse("access-token", "refresh-token", "not-a-jwt", 300, nil))

	_, err := c.exchange(context.Background(), "code", "verifier", "n0nce")
	wantOIDCError(t, err, oidcErrMalformed)
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
