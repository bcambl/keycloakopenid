package keycloakopenid

import (
	"crypto/tls"
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

func generateSessionID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
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

func (k *keycloakAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	for _, substr := range k.IgnorePathPrefixes {
		if strings.Contains(req.URL.Path, substr) {
			k.next.ServeHTTP(rw, req)
			return
		}
	}

	cookie, err := req.Cookie("SessionID")
	if err == nil {
		sessionID := cookie.Value
		token, exists := k.SessionStore.Get(sessionID)
		if exists {
			ok, err := k.verifyToken(token)
			if err != nil {
				http.Error(rw, err.Error(), http.StatusInternalServerError)
				return
			}
			if !ok {
				k.clearSessionCookie(rw)
				k.redirectToKeycloak(rw, req)
				return
			}

			user, err := extractClaims(token, k.UserClaimName)
			if err == nil {
				req.Header.Set(k.UserHeaderName, user)
			}

			if k.UseAuthHeader {
				req.Header.Set("Authorization", "Bearer "+token)
			}

			k.next.ServeHTTP(rw, req)
			return
		}
	}

	authCode := req.URL.Query().Get("code")
	if authCode == "" {
		k.redirectToKeycloak(rw, req)
		return
	}

	stateBase64 := req.URL.Query().Get("state")
	if stateBase64 == "" {
		k.redirectToKeycloak(rw, req)
		return
	}

	token, err := k.exchangeAuthCode(authCode, stateBase64)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	sessionID := generateSessionID()
	k.SessionStore.Set(sessionID, token, time.Hour) // Set token with 1-hour TTL

	sessionCookie := &http.Cookie{
		Name:     "SessionID",
		Value:    sessionID,
		Secure:   k.SecureCookie,
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

	http.Redirect(rw, req, originalURL, http.StatusTemporaryRedirect)
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

func (k *keycloakAuth) exchangeAuthCode(authCode, stateBase64 string) (string, error) {
	stateBytes, _ := base64.StdEncoding.DecodeString(stateBase64)
	var state state
	err := json.Unmarshal(stateBytes, &state)
	if err != nil {
		return "", err
	}

	target := k.KeycloakURL.JoinPath(
		"realms",
		k.KeycloakRealm,
		"protocol",
		"openid-connect",
		"token",
	)

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: k.InsecureSkipVerify}

	resp, err := http.PostForm(target.String(),
		url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {k.ClientID},
			"client_secret": {k.ClientSecret},
			"code":          {authCode},
			"redirect_uri":  {state.RedirectURL},
		})

	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", errors.New("received bad response from Keycloak: " + string(body))
	}

	var tokenResponse KeycloakTokenResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenResponse)
	if err != nil {
		return "", err
	}

	return tokenResponse.AccessToken, nil
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

	http.Redirect(rw, req, redirectURL.String(), http.StatusTemporaryRedirect)
}

func (k *keycloakAuth) verifyToken(token string) (bool, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: k.InsecureSkipVerify},
	}

	client := &http.Client{Transport: tr}

	data := url.Values{
		"token":         {token},
		"client_id":     {k.ClientID},
		"client_secret": {k.ClientSecret},
	}

	req, err := http.NewRequest(
		http.MethodPost,
		k.KeycloakURL.JoinPath(
			"realms",
			k.KeycloakRealm,
			"protocol",
			"openid-connect",
			"token",
			"introspect",
		).String(),
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return false, err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	var introspectResponse map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&introspectResponse)
	if err != nil {
		return false, err
	}

	return introspectResponse["active"].(bool), nil
}
