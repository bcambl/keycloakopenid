package keycloakopenid

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func generateSessionID() (string, error) {
	randomBytes := make([]byte, 64)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(randomBytes), nil
}

// pkceChallenge derives the S256 PKCE code challenge for a verifier.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func isNavigationRequest(req *http.Request) bool {
	if req.Method != http.MethodGet {
		return false
	}
	switch req.Header.Get("Sec-Fetch-Mode") {
	case "navigate":
		return true
	case "":
	default:
		return false
	}
	if req.Header.Get("X-Requested-With") == "XMLHttpRequest" {
		return false
	}
	return strings.Contains(req.Header.Get("Accept"), "text/html")
}

// isIgnoredPath reports whether path is covered by a configured ignored prefix
// using path-segment matching: a prefix matches the exact path or a path that
// begins with the prefix followed by a slash.
func (k *keycloakAuth) isIgnoredPath(path string) bool {
	for _, prefix := range k.IgnorePathPrefixes {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

func (k *keycloakAuth) isCallbackPath(path string) bool {
	return k.CallbackURL != nil && path == k.CallbackURL.Path
}

func validRequestPath(u *url.URL) bool {
	if u == nil {
		return false
	}
	rawPath := u.RawPath
	if rawPath == "" {
		rawPath = u.EscapedPath()
	}
	lowerPath := strings.ToLower(rawPath)
	if strings.Contains(lowerPath, "%2f") || strings.Contains(lowerPath, "%5c") || strings.Contains(lowerPath, "%00") {
		return false
	}
	decodedPath, err := url.PathUnescape(rawPath)
	if err != nil || unsafeReturnTarget(rawPath) || unsafeReturnTarget(decodedPath) {
		return false
	}
	for _, segment := range strings.Split(decodedPath, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func (k *keycloakAuth) writeUnauthorized(rw http.ResponseWriter) {
	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Cache-Control", "no-store")
	rw.WriteHeader(http.StatusUnauthorized)
	_, _ = io.WriteString(rw, `{"error":"authentication_required"}`+"\n")
}

func (k *keycloakAuth) writeBadRequest(rw http.ResponseWriter) {
	rw.Header().Set("Cache-Control", "no-store")
	http.Error(rw, "invalid authentication request", http.StatusBadRequest)
}

func (k *keycloakAuth) writeUnavailable(rw http.ResponseWriter) {
	rw.Header().Set("Cache-Control", "no-store")
	http.Error(rw, "authentication service unavailable", http.StatusBadGateway)
}

func (k *keycloakAuth) requireAuthentication(rw http.ResponseWriter, req *http.Request) {
	if !isNavigationRequest(req) {
		k.writeUnauthorized(rw)
		return
	}
	k.startLogin(rw, req)
}

// terminateSession ends an authenticated session: it deletes it from the store,
// clears the session cookie, and requires the client to authenticate again.
func (k *keycloakAuth) terminateSession(rw http.ResponseWriter, req *http.Request, sessionID string) {
	k.SessionStore.Delete(sessionID)
	http.SetCookie(rw, clearSessionCookie(k.clientKey))
	k.requireAuthentication(rw, req)
}

// startLogin begins a fresh authorization-code login for a navigation request.
func (k *keycloakAuth) startLogin(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Cache-Control", "no-store")

	rel := &url.URL{Path: req.URL.Path, RawPath: req.URL.RawPath, RawQuery: req.URL.RawQuery}
	returnTarget, err := safeReturnTarget(rel)
	if err != nil {
		returnTarget = "/"
	}

	state, nonce, verifier, err := k.loginStore.Begin(returnTarget)
	if err != nil {
		k.writeUnavailable(rw)
		return
	}

	authURL := k.oidc.authCodeURL(state, nonce, pkceChallenge(verifier))

	http.SetCookie(rw, loginCookie(k.clientKey, state))
	http.Redirect(rw, req, authURL, http.StatusSeeOther)
}

func (k *keycloakAuth) handleCallback(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Cache-Control", "no-store")

	state := req.URL.Query().Get("state")
	if state != "" {
		http.SetCookie(rw, clearLoginCookie(k.clientKey, state))
	}

	if req.Method != http.MethodGet {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if iss := req.URL.Query().Get("iss"); iss != "" && iss != k.issuer {
		k.writeBadRequest(rw)
		return
	}

	code := req.URL.Query().Get("code")
	if code == "" || state == "" {
		k.writeBadRequest(rw)
		return
	}

	cookie, err := req.Cookie(loginCookieName(k.clientKey, state))
	if err != nil || cookie.Value != state {
		k.writeBadRequest(rw)
		return
	}

	tx, ok := k.loginStore.Consume(state)
	if !ok {
		k.writeBadRequest(rw)
		return
	}

	ts, err := k.oidc.exchange(req.Context(), code, tx.verifier, tx.nonce)
	if err != nil {
		k.writeUnavailable(rw)
		return
	}

	session := &Session{}
	session.applyTokenSet(ts)

	sessionID, err := generateSessionID()
	if err != nil {
		k.writeUnavailable(rw)
		return
	}
	k.SessionStore.Set(sessionID, session)
	http.SetCookie(rw, sessionCookie(k.clientKey, sessionID))

	http.Redirect(rw, req, resolveReturnTarget(k.CallbackURL, tx.returnTarget), http.StatusSeeOther)
}

// resolveReturnTarget restores a stored relative return target against the
// configured callback origin.
func resolveReturnTarget(callback *url.URL, target string) string {
	rel, err := url.Parse(target)
	if err != nil || !isSafeReturnTarget(target) {
		return (&url.URL{Scheme: callback.Scheme, Host: callback.Host, Path: "/"}).String()
	}
	return callback.ResolveReference(rel).String()
}

func (k *keycloakAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Strip the configured user header and any incoming Authorization before
	// routing; only validated sessions may reintroduce them.
	req.Header.Del(k.UserHeaderName)
	req.Header.Del("Authorization")

	if !validRequestPath(req.URL) {
		k.writeBadRequest(rw)
		return
	}

	if k.isCallbackPath(req.URL.Path) {
		k.handleCallback(rw, req)
		return
	}

	if k.isIgnoredPath(req.URL.Path) {
		req.Header.Del(k.UserHeaderName)
		req.Header.Del("Authorization")
		k.next.ServeHTTP(rw, req)
		return
	}

	if sessionID, ok := k.sessionID(req); ok {
		if session, exists := k.SessionStore.Get(sessionID); exists {
			k.serveSession(rw, req, sessionID, session)
			return
		}
		http.SetCookie(rw, clearSessionCookie(k.clientKey))
		k.requireAuthentication(rw, req)
		return
	}

	k.requireAuthentication(rw, req)
}

func (k *keycloakAuth) sessionID(req *http.Request) (string, bool) {
	cookie, err := req.Cookie(sessionCookieName(k.clientKey))
	if err != nil || cookie.Value == "" {
		return "", false
	}
	return cookie.Value, true
}

func (k *keycloakAuth) serveSession(rw http.ResponseWriter, req *http.Request, sessionID string, session *Session) {
	accessToken, _, expiresAt := session.snapshot()

	status, err := k.oidc.introspect(req.Context(), accessToken)
	if err != nil {
		k.writeUnavailable(rw)
		return
	}

	needsRenewal := false
	force := false
	switch status {
	case tokenInactive:
		needsRenewal = true
		force = true
	case tokenActive:
		if time.Until(expiresAt) <= k.RefreshBeforeExpiry {
			needsRenewal = true
		}
	}

	if needsRenewal {
		if err := k.renewSession(req.Context(), session, accessToken, force); err != nil {
			if isOIDCRefusal(err) {
				k.terminateSession(rw, req, sessionID)
				return
			}
			if force {
				k.writeUnavailable(rw)
				return
			}
		}
	}

	k.forwardSession(rw, req, session)
}

// renewSession refreshes the session under its lock. A concurrent caller that
// already rotated the observed access token makes this call a no-op.
func (k *keycloakAuth) renewSession(ctx context.Context, session *Session, observedAccessToken string, force bool) error {
	session.mu.Lock()
	defer session.mu.Unlock()

	if session.AccessToken != observedAccessToken {
		return nil
	}
	if !force && time.Until(session.ExpiresAt) > k.RefreshBeforeExpiry {
		return nil
	}

	ts, err := k.oidc.refresh(ctx, session.RefreshToken)
	if err != nil {
		return err
	}

	if ts.Identity.Subject != "" {
		if ts.Identity.Subject != session.Subject {
			return newOIDCError(oidcErrRefusal, errors.New("oidc: refresh changed the session subject"))
		}
		if _, present := ts.Identity.Claims["nonce"]; present && subtle.ConstantTimeCompare([]byte(ts.Identity.Nonce), []byte(session.Nonce)) != 1 {
			return newOIDCError(oidcErrRefusal, errors.New("oidc: refresh changed the session nonce"))
		}
		if !sameAudienceSet(session.Audience, ts.Identity.Audience) {
			return newOIDCError(oidcErrRefusal, errors.New("oidc: refresh changed the session audience"))
		}
	}

	session.applyTokenSetLocked(ts)
	return nil
}

func sameAudienceSet(first, second []string) bool {
	firstSet := make(map[string]struct{}, len(first))
	secondSet := make(map[string]struct{}, len(second))
	for _, audience := range first {
		firstSet[audience] = struct{}{}
	}
	for _, audience := range second {
		secondSet[audience] = struct{}{}
	}
	if len(firstSet) != len(secondSet) {
		return false
	}
	for audience := range firstSet {
		if _, ok := secondSet[audience]; !ok {
			return false
		}
	}
	return true
}

// forwardSession sets the validated user and, when configured, the bearer
// token, then hands the request to the next handler. It fails closed without
// calling next when the configured identity claim is absent or not a nonempty
// string.
func (k *keycloakAuth) forwardSession(rw http.ResponseWriter, req *http.Request, session *Session) {
	session.mu.Lock()
	raw := session.Claims[k.UserClaimName]
	session.mu.Unlock()

	user, ok := raw.(string)
	if !ok || user == "" {
		k.writeUnavailable(rw)
		return
	}

	req.Header.Set(k.UserHeaderName, user)
	if k.UseAuthHeader {
		accessToken, _, _ := session.snapshot()
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	k.next.ServeHTTP(rw, req)
}
