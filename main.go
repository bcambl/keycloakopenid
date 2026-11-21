package keycloakopenid

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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

func (k *keycloakAuth) clearSessionCookie(rw http.ResponseWriter) {
	expiration := time.Now().Add(-24 * time.Hour)
	newCookie := &http.Cookie{
		Name:    "SessionID",
		Value:   "",
		Path:    "/",
		Expires: expiration,
		MaxAge:  -1,
	}
	http.SetCookie(rw, newCookie)
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

func (k *keycloakAuth) redirectStatus() int {
	return http.StatusSeeOther
}

func (k *keycloakAuth) writeUnauthorized(rw http.ResponseWriter) {
	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Cache-Control", "no-store")
	rw.WriteHeader(http.StatusUnauthorized)
	_, _ = io.WriteString(rw, `{"error":"authentication_required"}`+"\n")
}

func (k *keycloakAuth) requireAuthentication(rw http.ResponseWriter, req *http.Request) {
	if !isNavigationRequest(req) {
		k.writeUnauthorized(rw)
		return
	}
	k.redirectToKeycloak(rw, req)
}

func (k *keycloakAuth) terminateSession(rw http.ResponseWriter, req *http.Request) {
	if cookie, err := req.Cookie("SessionID"); err == nil {
		k.SessionStore.Delete(cookie.Value)
	}
	k.clearSessionCookie(rw)
	k.requireAuthentication(rw, req)
}

func (k *keycloakAuth) forwardSession(rw http.ResponseWriter, req *http.Request, token string) {
	user, err := extractClaims(token, k.UserClaimName)
	if err == nil {
		req.Header.Set(k.UserHeaderName, user)
	}
	if k.UseAuthHeader {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	k.next.ServeHTTP(rw, req)
}

func (k *keycloakAuth) serveSession(rw http.ResponseWriter, req *http.Request, session *Session) {
	accessToken, _, expiresAt := session.snapshot()
	status, _ := k.introspectToken(accessToken)

	if status == tokenUnavailable {
		http.Error(rw, "Keycloak introspection unavailable", http.StatusBadGateway)
		return
	}

	if status == tokenInactive || time.Until(expiresAt) <= k.RefreshBeforeExpiry {
		if renewErr := k.renewSession(session); renewErr != nil {
			if isRefreshRefused(renewErr) {
				k.terminateSession(rw, req)
				return
			}
			if status == tokenInactive {
				http.Error(rw, "Keycloak renewal unavailable", http.StatusBadGateway)
				return
			}
		}
	}

	accessToken, _, _ = session.snapshot()
	k.forwardSession(rw, req, accessToken)
}

func (k *keycloakAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	for _, substr := range k.IgnorePathPrefixes {
		if strings.Contains(req.URL.Path, substr) {
			k.next.ServeHTTP(rw, req)
			return
		}
	}

	cookie, err := req.Cookie("SessionID")
	if err == nil {
		session, exists := k.SessionStore.Get(cookie.Value)
		if exists {
			k.serveSession(rw, req, session)
			return
		}
		k.terminateSession(rw, req)
		return
	}

	authCode := req.URL.Query().Get("code")
	if authCode == "" {
		k.requireAuthentication(rw, req)
		return
	}

	stateBase64 := req.URL.Query().Get("state")
	if stateBase64 == "" {
		k.requireAuthentication(rw, req)
		return
	}

	tokenResponse, err := k.exchangeAuthCode(authCode, stateBase64)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	if tokenResponse.RefreshToken == "" || tokenResponse.ExpiresIn <= 0 {
		http.Error(rw, "Keycloak token response cannot be silently renewed: refresh_token and expires_in are required", http.StatusInternalServerError)
		return
	}

	session := &Session{
		AccessToken:      tokenResponse.AccessToken,
		RefreshToken:     tokenResponse.RefreshToken,
		ExpiresAt:        time.Now().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second),
		RefreshExpiresAt: refreshExpiry(tokenResponse),
	}

	sessionID, err := generateSessionID()
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	k.SessionStore.Set(sessionID, session)

	sessionCookie := &http.Cookie{
		Name:     "SessionID",
		Value:    sessionID,
		Secure:   true,
		HttpOnly: true,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(rw, sessionCookie)
	req.AddCookie(sessionCookie)

	qry := req.URL.Query()
	qry.Del("code")
	qry.Del("state")
	qry.Del("session_state")
	req.URL.RawQuery = qry.Encode()
	req.RequestURI = req.URL.RequestURI()

	scheme := req.Header.Get("X-Forwarded-Proto")
	host := req.Header.Get("X-Forwarded-Host")
	originalURL := fmt.Sprintf("%s://%s%s", scheme, host, req.RequestURI)

	http.Redirect(rw, req, originalURL, k.redirectStatus())
}

func extractClaims(tokenString, claimName string) (string, error) {
	jwtContent := strings.Split(tokenString, ".")
	if len(jwtContent) < 3 {
		return "", fmt.Errorf("malformed jwt")
	}

	var jwtClaims map[string]interface{}
	decoder := base64.StdEncoding.WithPadding(base64.NoPadding)

	jwtBytes, _ := decoder.DecodeString(jwtContent[1])
	if err := json.Unmarshal(jwtBytes, &jwtClaims); err != nil {
		return "", err
	}

	if claimValue, ok := jwtClaims[claimName]; ok {
		return fmt.Sprintf("%v", claimValue), nil
	}
	return "", fmt.Errorf("missing claim %s", claimName)
}

func (k *keycloakAuth) exchangeAuthCode(authCode, stateBase64 string) (*KeycloakTokenResponse, error) {
	stateBytes, _ := base64.StdEncoding.DecodeString(stateBase64)
	var state state
	err := json.Unmarshal(stateBytes, &state)
	if err != nil {
		return nil, err
	}

	target := k.KeycloakURL.JoinPath(
		"realms",
		k.KeycloakRealm,
		"protocol",
		"openid-connect",
		"token",
	)

	resp, err := k.upstream.PostForm(target.String(),
		url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {k.ClientID},
			"client_secret": {k.ClientSecret},
			"code":          {authCode},
			"redirect_uri":  {state.RedirectURL},
		})

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, &keycloakError{Status: resp.StatusCode, Body: string(body)}
	}

	var tokenResponse KeycloakTokenResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenResponse)
	if err != nil {
		return nil, err
	}

	return &tokenResponse, nil
}

type keycloakError struct {
	Status int
	Body   string
}

func (e *keycloakError) Error() string {
	return "received bad response from Keycloak: " + e.Body
}

func isRefreshRefused(err error) bool {
	var kcErr *keycloakError
	if !errors.As(err, &kcErr) {
		return false
	}
	return (kcErr.Status == http.StatusBadRequest || kcErr.Status == http.StatusUnauthorized) &&
		strings.Contains(kcErr.Body, "invalid_grant")
}

func (k *keycloakAuth) refreshAccessToken(refreshToken string) (*KeycloakTokenResponse, error) {
	target := k.KeycloakURL.JoinPath(
		"realms",
		k.KeycloakRealm,
		"protocol",
		"openid-connect",
		"token",
	)

	resp, err := k.upstream.PostForm(target.String(), url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {k.ClientID},
		"client_secret": {k.ClientSecret},
		"refresh_token": {refreshToken},
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, &keycloakError{Status: resp.StatusCode, Body: string(body)}
	}

	var tokenResponse KeycloakTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, err
	}
	if tokenResponse.ExpiresIn <= 0 {
		return nil, errors.New("missing expires_in")
	}

	return &tokenResponse, nil
}

func (k *keycloakAuth) renewSession(s *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if time.Until(s.ExpiresAt) > k.RefreshBeforeExpiry {
		return nil
	}

	tokenResponse, err := k.refreshAccessToken(s.RefreshToken)
	if err != nil {
		return err
	}
	if tokenResponse.AccessToken == "" {
		return errors.New("missing access_token")
	}

	s.AccessToken = tokenResponse.AccessToken
	if tokenResponse.RefreshToken != "" {
		s.RefreshToken = tokenResponse.RefreshToken
	}
	s.ExpiresAt = time.Now().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second)
	s.RefreshExpiresAt = refreshExpiry(tokenResponse)
	return nil
}

// refreshExpiry is zero when Keycloak reports no refresh-token expiry, for
// example for offline tokens, so such sessions are never evicted as expired.
func refreshExpiry(tokenResponse *KeycloakTokenResponse) time.Time {
	if tokenResponse.RefreshExpiresIn <= 0 {
		return time.Time{}
	}
	return time.Now().Add(time.Duration(tokenResponse.RefreshExpiresIn) * time.Second)
}

func (k *keycloakAuth) redirectToKeycloak(rw http.ResponseWriter, req *http.Request) {
	scheme := req.Header.Get("X-Forwarded-Proto")
	host := req.Header.Get("X-Forwarded-Host")
	originalURL := fmt.Sprintf("%s://%s%s", scheme, host, req.RequestURI)

	state := state{
		RedirectURL: originalURL,
	}

	stateBytes, _ := json.Marshal(state)
	stateBase64 := base64.StdEncoding.EncodeToString(stateBytes)

	redirectURL := k.KeycloakURL.JoinPath(
		"realms",
		k.KeycloakRealm,
		"protocol",
		"openid-connect",
		"auth",
	)
	redirectURL.RawQuery = url.Values{
		"response_type": {"code"},
		"client_id":     {k.ClientID},
		"redirect_uri":  {originalURL},
		"state":         {stateBase64},
		"scope":         {k.Scope},
	}.Encode()

	http.Redirect(rw, req, redirectURL.String(), k.redirectStatus())
}

type tokenStatus int

const (
	tokenActive tokenStatus = iota
	tokenInactive
	tokenUnavailable
)

func (k *keycloakAuth) introspectToken(token string) (tokenStatus, error) {
	data := url.Values{
		"token":         {token},
		"client_id":     {k.ClientID},
		"client_secret": {k.ClientSecret},
	}

	resp, err := k.upstream.PostForm(
		k.KeycloakURL.JoinPath(
			"realms",
			k.KeycloakRealm,
			"protocol",
			"openid-connect",
			"token",
			"introspect",
		).String(),
		data,
	)
	if err != nil {
		return tokenUnavailable, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return tokenUnavailable, nil
	}

	var introspectResponse struct {
		Active bool `json:"active"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&introspectResponse); err != nil {
		return tokenUnavailable, err
	}

	if introspectResponse.Active {
		return tokenActive, nil
	}
	return tokenInactive, nil
}
