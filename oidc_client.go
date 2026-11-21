package keycloakopenid

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// runtimeConfig carries the validated configuration an OIDC client needs. It is
// the boundary between the middleware constructor and the standalone client.
type runtimeConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	CallbackURL  string
	Scope        string
	Upstream     *http.Client
}

// oidcClient is a standalone OpenID Connect client backed by provider
// discovery and cached JWKS verification.
type oidcClient struct {
	clientID         string
	clientSecret     string
	oauth            *oauth2.Config
	parser           *jwt.Parser
	jwks             *jwksCache
	introspectionURL string
	upstream         *http.Client
}

type validatedIDToken struct {
	Subject         string
	Nonce           string
	Audience        []string
	AccessTokenHash string
	Algorithm       string
	Claims          jwt.MapClaims
}

// identity carries the validated claims of a signed ID token.
type identity struct {
	Subject string
	Claims  map[string]any
}

// tokenSet carries the tokens and validated identity produced by an exchange
// or refresh. RefreshExpiresIn is nil when the field is omitted, 0 for no fixed
// expiry, and positive for a concrete expiry in seconds.
//
// A zero Identity (empty Subject and nil Claims) means the response carried no
// ID token; the caller must preserve its existing identity. A non-empty Subject
// is the validated subject from a returned ID token, which the caller must
// compare against the established subject before applying the token set.
type tokenSet struct {
	AccessToken      string
	RefreshToken     string
	ExpiresIn        int
	RefreshExpiresIn *int
	Identity         identity
}

// tokenStatus classifies the result of introspecting an access token.
type tokenStatus int

const (
	tokenActive tokenStatus = iota
	tokenInactive
	tokenUnavailable
)

type oidcErrKind int

const (
	oidcErrRefusal oidcErrKind = iota
	oidcErrOutage
	oidcErrMalformed
)

// oidcError classifies an upstream failure as a refusal, an outage, or a
// malformed response without exposing the upstream body.
type oidcError struct {
	kind oidcErrKind
	err  error
}

func (e *oidcError) Error() string { return e.err.Error() }
func (e *oidcError) Unwrap() error { return e.err }

func newOIDCError(kind oidcErrKind, err error) error {
	return &oidcError{kind: kind, err: err}
}

func isOIDCRefusal(err error) bool {
	var oe *oidcError
	return errors.As(err, &oe) && oe.kind == oidcErrRefusal
}

func newOIDCClient(ctx context.Context, cfg runtimeConfig) (*oidcClient, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("oidc: issuer is required")
	}
	if cfg.ClientID == "" {
		return nil, errors.New("oidc: client id is required")
	}
	if cfg.Upstream == nil {
		return nil, errors.New("oidc: upstream client is required")
	}

	provider, err := discoverProvider(ctx, cfg)
	if err != nil {
		return nil, err
	}
	algs, err := signingAlgorithms(provider.algorithms)
	if err != nil {
		return nil, newOIDCError(oidcErrMalformed, err)
	}

	oauth := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:   provider.authURL,
			TokenURL:  provider.tokenURL,
			AuthStyle: oauth2.AuthStyleInParams,
		},
		Scopes: oauthScopes(cfg.Scope),
	}
	parser := jwt.NewParser(
		jwt.WithValidMethods(algs),
		jwt.WithIssuer(cfg.Issuer),
		jwt.WithAudience(cfg.ClientID),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(time.Minute),
	)

	return &oidcClient{
		clientID:         cfg.ClientID,
		clientSecret:     cfg.ClientSecret,
		oauth:            oauth,
		parser:           parser,
		jwks:             &jwksCache{client: cfg.Upstream, url: provider.jwksURL},
		introspectionURL: provider.introspectionURL,
		upstream:         cfg.Upstream,
	}, nil
}

type providerMetadata struct {
	authURL          string
	tokenURL         string
	jwksURL          string
	introspectionURL string
	algorithms       []string
}

// discoverProvider fetches and validates provider metadata without exposing
// the upstream response body.
func discoverProvider(ctx context.Context, cfg runtimeConfig) (providerMetadata, error) {
	wellKnown := strings.TrimSuffix(cfg.Issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return providerMetadata{}, newOIDCError(oidcErrMalformed, errors.New("oidc: invalid discovery endpoint"))
	}

	resp, err := cfg.Upstream.Do(req)
	if err != nil {
		return providerMetadata{}, newOIDCError(oidcErrOutage, errors.New("oidc: discovery unavailable"))
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxUpstreamResponse+1))
	if err != nil {
		return providerMetadata{}, newOIDCError(oidcErrMalformed, errors.New("oidc: discovery response unreadable"))
	}
	if len(body) > maxUpstreamResponse {
		return providerMetadata{}, newOIDCError(oidcErrMalformed, errors.New("oidc: discovery response exceeds limit"))
	}
	if resp.StatusCode != http.StatusOK {
		return providerMetadata{}, newOIDCError(discoveryErrorKind(resp.StatusCode), fmt.Errorf("oidc: discovery returned status %d", resp.StatusCode))
	}

	var doc struct {
		Issuer        string   `json:"issuer"`
		AuthURL       string   `json:"authorization_endpoint"`
		TokenURL      string   `json:"token_endpoint"`
		JWKSURL       string   `json:"jwks_uri"`
		Introspection string   `json:"introspection_endpoint"`
		Algorithms    []string `json:"id_token_signing_alg_values_supported"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return providerMetadata{}, newOIDCError(oidcErrMalformed, errors.New("oidc: malformed discovery document"))
	}
	if doc.Issuer != cfg.Issuer {
		return providerMetadata{}, newOIDCError(oidcErrMalformed, errors.New("oidc: issuer mismatch"))
	}
	for _, endpoint := range []string{doc.AuthURL, doc.TokenURL, doc.JWKSURL} {
		if !validProviderURL(endpoint) {
			return providerMetadata{}, newOIDCError(oidcErrMalformed, errors.New("oidc: discovery contains invalid endpoint"))
		}
	}
	if doc.Introspection != "" && !validProviderURL(doc.Introspection) {
		return providerMetadata{}, newOIDCError(oidcErrMalformed, errors.New("oidc: discovery contains invalid introspection endpoint"))
	}

	introspectionURL := doc.Introspection
	if introspectionURL == "" {
		introspectionURL = strings.TrimSuffix(cfg.Issuer, "/") + "/protocol/openid-connect/token/introspect"
	}
	return providerMetadata{
		authURL:          doc.AuthURL,
		tokenURL:         doc.TokenURL,
		jwksURL:          doc.JWKSURL,
		introspectionURL: introspectionURL,
		algorithms:       doc.Algorithms,
	}, nil
}

func validProviderURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Scheme, "http") || strings.EqualFold(u.Scheme, "https")
}

func discoveryErrorKind(status int) oidcErrKind {
	if status == http.StatusBadRequest || status == http.StatusUnauthorized {
		return oidcErrRefusal
	}
	if status >= 500 {
		return oidcErrOutage
	}
	return oidcErrMalformed
}

var asymmetricSigningAlgs = map[string]bool{
	"RS256": true, "RS384": true, "RS512": true,
	"ES256": true, "ES384": true, "ES512": true,
	"PS256": true, "PS384": true, "PS512": true,
	"EdDSA": true,
}

// signingAlgorithms returns the provider-advertised signing algorithms
// restricted to asymmetric ones. When the provider advertises none, the OIDC
// default RS256 applies; when it advertises only non-asymmetric algorithms,
// signing is impossible and an error is returned.
func signingAlgorithms(advertised []string) ([]string, error) {
	if len(advertised) == 0 {
		return []string{"RS256"}, nil
	}
	var algs []string
	for _, a := range advertised {
		if asymmetricSigningAlgs[a] {
			algs = append(algs, a)
		}
	}
	if len(algs) == 0 {
		return nil, errors.New("oidc: provider supports no asymmetric id token signing algorithms")
	}
	return algs, nil
}

func oauthScopes(scope string) []string {
	return strings.Fields(ensureOpenIDScope(scope))
}

func (c *oidcClient) withClient(ctx context.Context) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, c.upstream)
}

func (c *oidcClient) authCodeURL(state, nonce, codeChallenge string) string {
	return c.oauth.AuthCodeURL(state,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

func (c *oidcClient) exchange(ctx context.Context, code, verifier, nonce string) (*tokenSet, error) {
	tok, err := c.oauth.Exchange(c.withClient(ctx), code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, sanitizeOAuthErr(err)
	}
	if tok.AccessToken == "" {
		return nil, newOIDCError(oidcErrMalformed, errors.New("oidc: token response missing access_token"))
	}
	if tok.RefreshToken == "" {
		return nil, newOIDCError(oidcErrMalformed, errors.New("oidc: token response missing refresh_token"))
	}

	rawID, _ := tok.Extra("id_token").(string)
	idToken, err := c.validateIDToken(ctx, rawID, tok.AccessToken)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(nonce)) != 1 {
		return nil, newOIDCError(oidcErrMalformed, errors.New("oidc: id token nonce mismatch"))
	}

	return c.buildTokenSet(tok, idToken)
}

func (c *oidcClient) refresh(ctx context.Context, refreshToken string) (*tokenSet, error) {
	tok, err := c.oauth.TokenSource(c.withClient(ctx), &oauth2.Token{RefreshToken: refreshToken}).Token()
	if err != nil {
		return nil, sanitizeOAuthErr(err)
	}

	rawIDValue := tok.Extra("id_token")
	rawID, ok := rawIDValue.(string)
	if rawIDValue != nil && !ok {
		return nil, newOIDCError(oidcErrMalformed, errors.New("oidc: token response has invalid id_token"))
	}
	var idToken *validatedIDToken
	if rawID != "" {
		idToken, err = c.validateIDToken(ctx, rawID, tok.AccessToken)
		if err != nil {
			return nil, err
		}
	}

	return c.buildTokenSet(tok, idToken)
}

// validateIDToken verifies the signature, registered claims, authorized party,
// and access-token hash of an ID token. The nonce is validated by the caller.
func (c *oidcClient) validateIDToken(ctx context.Context, rawID, accessToken string) (*validatedIDToken, error) {
	if rawID == "" {
		return nil, newOIDCError(oidcErrMalformed, errors.New("oidc: token response missing id_token"))
	}

	claims := jwt.MapClaims{}
	token, err := c.parser.ParseWithClaims(rawID, claims, func(token *jwt.Token) (any, error) {
		return c.jwks.verificationKey(ctx, token)
	})
	if err != nil || token == nil || !token.Valid {
		return nil, newOIDCError(oidcErrMalformed, errors.New("oidc: id token validation failed"))
	}

	subject, err := claims.GetSubject()
	if err != nil || subject == "" {
		return nil, newOIDCError(oidcErrMalformed, errors.New("oidc: id token missing valid subject"))
	}
	audience, err := claims.GetAudience()
	if err != nil {
		return nil, newOIDCError(oidcErrMalformed, errors.New("oidc: id token has invalid audience"))
	}
	nonce, err := idTokenStringClaim(claims, "nonce")
	if err != nil {
		return nil, newOIDCError(oidcErrMalformed, err)
	}
	atHash, err := idTokenStringClaim(claims, "at_hash")
	if err != nil {
		return nil, newOIDCError(oidcErrMalformed, err)
	}
	idToken := &validatedIDToken{
		Subject:         subject,
		Nonce:           nonce,
		Audience:        []string(audience),
		AccessTokenHash: atHash,
		Algorithm:       token.Method.Alg(),
		Claims:          claims,
	}
	if err := c.checkAuthorizedParty(idToken); err != nil {
		return nil, newOIDCError(oidcErrMalformed, err)
	}
	if _, present := claims["at_hash"]; present {
		if err := verifyAccessTokenHash(accessToken, atHash, idToken.Algorithm); err != nil {
			return nil, newOIDCError(oidcErrMalformed, err)
		}
	}
	return idToken, nil
}

func idTokenStringClaim(claims jwt.MapClaims, name string) (string, error) {
	raw, ok := claims[name]
	if !ok {
		return "", nil
	}
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("oidc: id token has invalid %s claim", name)
	}
	return value, nil
}

// checkAuthorizedParty requires multiple audiences to identify this client and
// rejects any explicitly provided authorized party for another client.
func (c *oidcClient) checkAuthorizedParty(idToken *validatedIDToken) error {
	raw, present := idToken.Claims["azp"]
	if !present && len(idToken.Audience) <= 1 {
		return nil
	}
	authorizedParty, ok := raw.(string)
	if !ok || authorizedParty != c.clientID {
		return errors.New("oidc: id token missing valid authorized party")
	}
	return nil
}

func verifyAccessTokenHash(accessToken, expected, alg string) error {
	var digest []byte
	switch alg {
	case "RS256", "PS256", "ES256":
		sum := sha256.Sum256([]byte(accessToken))
		digest = sum[:]
	case "RS384", "PS384", "ES384":
		sum := sha512.Sum384([]byte(accessToken))
		digest = sum[:]
	case "RS512", "PS512", "ES512", "EdDSA":
		sum := sha512.Sum512([]byte(accessToken))
		digest = sum[:]
	default:
		return errors.New("oidc: unsupported id token signing algorithm")
	}
	actual := base64.RawURLEncoding.EncodeToString(digest[:len(digest)/2])
	if subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) != 1 {
		return errors.New("oidc: id token access token hash mismatch")
	}
	return nil
}

func (c *oidcClient) buildTokenSet(tok *oauth2.Token, idToken *validatedIDToken) (*tokenSet, error) {
	refreshExp, err := refreshExpirySeconds(tok)
	if err != nil {
		return nil, newOIDCError(oidcErrMalformed, err)
	}

	ts := &tokenSet{
		AccessToken:      tok.AccessToken,
		RefreshToken:     tok.RefreshToken,
		ExpiresIn:        int(tok.ExpiresIn),
		RefreshExpiresIn: refreshExp,
	}
	if idToken != nil {
		ts.Identity = identity{Subject: idToken.Subject, Claims: map[string]any(idToken.Claims)}
	}
	return ts, nil
}

// refreshExpirySeconds converts the provider's refresh_expires_in field into
// the pointer form carried by tokenSet: nil when omitted, a non-nil value
// otherwise. A negative value is invalid.
func refreshExpirySeconds(tok *oauth2.Token) (*int, error) {
	v := tok.Extra("refresh_expires_in")
	if v == nil {
		return nil, nil
	}
	f, ok := v.(float64)
	if !ok {
		return nil, errors.New("oidc: invalid refresh_expires_in")
	}
	i := int(f)
	if i < 0 {
		return nil, errors.New("oidc: invalid refresh_expires_in")
	}
	return &i, nil
}

// sanitizeOAuthErr maps an error from the OAuth2 token flow to a classified
// oidcError, discarding the upstream body. Context cancellation and deadline
// errors are propagated unchanged so callers can distinguish them.
func sanitizeOAuthErr(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var re *oauth2.RetrieveError
	if errors.As(err, &re) {
		code := re.Response.StatusCode
		switch {
		case code == http.StatusBadRequest || code == http.StatusUnauthorized:
			return newOIDCError(oidcErrRefusal, fmt.Errorf("oidc: token endpoint refused the request (status %d)", code))
		case code >= 500:
			return newOIDCError(oidcErrOutage, fmt.Errorf("oidc: token endpoint unavailable (status %d)", code))
		default:
			return newOIDCError(oidcErrMalformed, fmt.Errorf("oidc: unexpected token endpoint response (status %d)", code))
		}
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		return newOIDCError(oidcErrOutage, errors.New("oidc: token endpoint unreachable"))
	}
	return newOIDCError(oidcErrMalformed, errors.New("oidc: malformed token response"))
}

func (c *oidcClient) introspect(ctx context.Context, accessToken string) (tokenStatus, error) {
	form := url.Values{
		"token":         {accessToken},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.introspectionURL, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenUnavailable, newOIDCError(oidcErrMalformed, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.upstream.Do(req)
	if err != nil {
		return tokenUnavailable, newOIDCError(oidcErrOutage, errors.New("oidc: introspection unavailable"))
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == http.StatusOK:
		var r struct {
			Active bool `json:"active"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
			return tokenUnavailable, newOIDCError(oidcErrMalformed, errors.New("oidc: malformed introspection response"))
		}
		if r.Active {
			return tokenActive, nil
		}
		return tokenInactive, nil
	case resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized:
		return tokenUnavailable, newOIDCError(oidcErrRefusal, fmt.Errorf("oidc: introspection refused (status %d)", resp.StatusCode))
	case resp.StatusCode >= 500:
		return tokenUnavailable, newOIDCError(oidcErrOutage, fmt.Errorf("oidc: introspection unavailable (status %d)", resp.StatusCode))
	default:
		return tokenUnavailable, newOIDCError(oidcErrMalformed, fmt.Errorf("oidc: unexpected introspection response (status %d)", resp.StatusCode))
	}
}
