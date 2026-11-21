package keycloakopenid

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
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
	verifier         *oidc.IDTokenVerifier
	introspectionURL string
	upstream         *http.Client
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

func isOIDCOutage(err error) bool {
	var oe *oidcError
	return errors.As(err, &oe) && oe.kind == oidcErrOutage
}

func isOIDCMalformed(err error) bool {
	var oe *oidcError
	return errors.As(err, &oe) && oe.kind == oidcErrMalformed
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

	provider, introspectionURL, advertised, err := discoverProvider(ctx, cfg)
	if err != nil {
		return nil, err
	}

	algs, err := signingAlgorithms(advertised)
	if err != nil {
		return nil, newOIDCError(oidcErrMalformed, err)
	}

	endpoint := provider.Endpoint()
	endpoint.AuthStyle = oauth2.AuthStyleInParams

	oauth := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.CallbackURL,
		Endpoint:     endpoint,
		Scopes:       oauthScopes(cfg.Scope),
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID:             cfg.ClientID,
		SupportedSigningAlgs: algs,
	})

	return &oidcClient{
		clientID:         cfg.ClientID,
		clientSecret:     cfg.ClientSecret,
		oauth:            oauth,
		verifier:         verifier,
		introspectionURL: introspectionURL,
		upstream:         cfg.Upstream,
	}, nil
}

// discoverProvider fetches the OpenID Connect discovery document and builds a
// provider from it. Discovery failures are classified without exposing the
// upstream body.
func discoverProvider(ctx context.Context, cfg runtimeConfig) (*oidc.Provider, string, []string, error) {
	wellKnown := strings.TrimSuffix(cfg.Issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return nil, "", nil, newOIDCError(oidcErrMalformed, err)
	}

	resp, err := cfg.Upstream.Do(req)
	if err != nil {
		return nil, "", nil, newOIDCError(oidcErrOutage, errors.New("oidc: discovery unavailable"))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxUpstreamResponse+1))
	if err != nil {
		return nil, "", nil, newOIDCError(oidcErrMalformed, errors.New("oidc: discovery response unreadable"))
	}
	if len(body) > maxUpstreamResponse {
		return nil, "", nil, newOIDCError(oidcErrMalformed, errors.New("oidc: discovery response exceeds limit"))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, "", nil, newOIDCError(discoveryErrorKind(resp.StatusCode), fmt.Errorf("oidc: discovery returned status %d", resp.StatusCode))
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
		return nil, "", nil, newOIDCError(oidcErrMalformed, errors.New("oidc: malformed discovery document"))
	}
	if doc.Issuer != cfg.Issuer {
		return nil, "", nil, newOIDCError(oidcErrMalformed, errors.New("oidc: issuer mismatch"))
	}

	provider := (&oidc.ProviderConfig{
		IssuerURL:  doc.Issuer,
		AuthURL:    doc.AuthURL,
		TokenURL:   doc.TokenURL,
		JWKSURL:    doc.JWKSURL,
		Algorithms: doc.Algorithms,
	}).NewProvider(oidc.ClientContext(ctx, cfg.Upstream))

	introspectionURL := doc.Introspection
	if introspectionURL == "" {
		introspectionURL = strings.TrimSuffix(cfg.Issuer, "/") + "/protocol/openid-connect/token/introspect"
	}

	return provider, introspectionURL, doc.Algorithms, nil
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
	return oidc.ClientContext(ctx, c.upstream)
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
	if idToken.Nonce != nonce {
		return nil, newOIDCError(oidcErrMalformed, errors.New("oidc: id token nonce mismatch"))
	}

	return c.buildTokenSet(tok, idToken)
}

func (c *oidcClient) refresh(ctx context.Context, refreshToken string) (*tokenSet, error) {
	tok, err := c.oauth.TokenSource(c.withClient(ctx), &oauth2.Token{RefreshToken: refreshToken}).Token()
	if err != nil {
		return nil, sanitizeOAuthErr(err)
	}

	rawID, _ := tok.Extra("id_token").(string)
	var idToken *oidc.IDToken
	if rawID != "" {
		idToken, err = c.validateIDToken(ctx, rawID, tok.AccessToken)
		if err != nil {
			return nil, err
		}
	}

	return c.buildTokenSet(tok, idToken)
}

// validateIDToken verifies the signature, issuer, audience, authorized party,
// expiry, and access-token hash of an ID token. The nonce is validated by the
// caller.
func (c *oidcClient) validateIDToken(ctx context.Context, rawID, accessToken string) (*oidc.IDToken, error) {
	if rawID == "" {
		return nil, newOIDCError(oidcErrMalformed, errors.New("oidc: token response missing id_token"))
	}
	idToken, err := c.verifier.Verify(ctx, rawID)
	if err != nil {
		return nil, newOIDCError(oidcErrMalformed, err)
	}
	if err := c.checkAuthorizedParty(idToken); err != nil {
		return nil, newOIDCError(oidcErrMalformed, err)
	}
	if idToken.AccessTokenHash != "" {
		if err := idToken.VerifyAccessToken(accessToken); err != nil {
			return nil, newOIDCError(oidcErrMalformed, err)
		}
	}
	return idToken, nil
}

// checkAuthorizedParty enforces the OIDC authorized-party rule: an ID token
// with multiple audiences must carry an azp claim identifying this client.
func (c *oidcClient) checkAuthorizedParty(idToken *oidc.IDToken) error {
	if len(idToken.Audience) <= 1 {
		return nil
	}
	var claims struct {
		AuthorizedParty string `json:"azp"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return err
	}
	if claims.AuthorizedParty != c.clientID {
		return errors.New("oidc: id token missing valid authorized party")
	}
	return nil
}

func (c *oidcClient) buildTokenSet(tok *oauth2.Token, idToken *oidc.IDToken) (*tokenSet, error) {
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
		var claims map[string]any
		if err := idToken.Claims(&claims); err != nil {
			return nil, newOIDCError(oidcErrMalformed, err)
		}
		ts.Identity = identity{Subject: idToken.Subject, Claims: claims}
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
	defer resp.Body.Close()

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
