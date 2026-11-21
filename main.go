package keycloakopenid

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
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
	u := url.URL{Scheme: callback.Scheme, Host: callback.Host}
	if i := strings.IndexByte(target, '?'); i >= 0 {
		u.Path = target[:i]
		u.RawQuery = target[i+1:]
	} else {
		u.Path = target
	}
	return u.String()
}

func (k *keycloakAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Strip the configured user header and any incoming Authorization before
	// routing; only validated sessions may reintroduce them.
	req.Header.Del(k.UserHeaderName)
	req.Header.Del("Authorization")

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
		if err := k.renewSession(req.Context(), session, force); err != nil {
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

// renewSession refreshes the session under its lock, rejecting a refreshed
// identity whose subject differs from the established subject. When force is
// false, a concurrent caller that already renewed the session to a fresh
// expiry causes this call to be skipped.
func (k *keycloakAuth) renewSession(ctx context.Context, session *Session, force bool) error {
	session.mu.Lock()
	defer session.mu.Unlock()

	if !force && time.Until(session.ExpiresAt) > k.RefreshBeforeExpiry {
		return nil
	}

	refreshToken := session.RefreshToken
	subject := session.Subject

	ts, err := k.oidc.refresh(ctx, refreshToken)
	if err != nil {
		return err
	}

	if ts.Identity.Subject != "" && subject != "" && ts.Identity.Subject != subject {
		return newOIDCError(oidcErrRefusal, errors.New("oidc: refresh changed the session subject"))
	}

	session.applyTokenSetLocked(ts)
	return nil
}

// forwardSession sets the validated user and, when configured, the bearer
// token, then hands the request to the next handler. It fails closed without
// calling next when the configured identity claim is absent or not a nonempty
// string.
func (k *keycloakAuth) forwardSession(rw http.ResponseWriter, req *http.Request, session *Session) {
	session.mu.Lock()
	raw, ok := session.Claims[k.UserClaimName]
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
