package keycloakopenid

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	KeycloakURL         string `json:"url"`
	InsecureSkipVerify  bool   `json:"insecure_skip_verify"`
	ClientID            string `json:"client_id"`
	ClientSecret        string `json:"client_secret"`
	KeycloakRealm       string `json:"keycloak_realm"`
	Scope               string `json:"scope"`
	UseAuthHeader       bool   `json:"use_auth_header"`
	UserClaimName       string `json:"user_claim_name"`
	UserHeaderName      string `json:"user_header_name"`
	IgnorePathPrefixes  string `json:"ignore_path_prefixes"`
	LegacySupport       bool   `json:"legacy_support"`
	RefreshBeforeExpiry string `json:"refresh_before_expiry"`
	CallbackURL         string `json:"callback_url"`
	SessionCapacity     int    `json:"session_capacity"`

	ClientIDFile           string `json:"client_id_file"`
	ClientSecretFile       string `json:"client_secret_file"`
	KeycloakURLEnv         string `json:"url_env"`
	InsecureSkipVerifyEnv  string `json:"insecure_skip_verify_env"`
	ClientIDEnv            string `json:"client_id_env"`
	ClientSecretEnv        string `json:"client_secret_env"`
	KeycloakRealmEnv       string `json:"keycloak_realm_env"`
	ScopeEnv               string `json:"scope_env"`
	UseAuthHeaderEnv       string `json:"use_auth_header_env"`
	IgnorePathPrefixesEnv  string `json:"ignore_path_prefixes_env"`
	LegacySupportEnv       string `json:"legacy_support_env"`
	RefreshBeforeExpiryEnv string `json:"refresh_before_expiry_env"`
}

// keycloakAuth is the middleware. It owns the validated OIDC client, the shared
// per-client session and login stores, and the fixed callback used to complete
// the authorization-code flow.
type keycloakAuth struct {
	next                http.Handler
	KeycloakURL         *url.URL // resolved base (after static legacy /auth selection)
	issuer              string   // KeycloakURL + /realms/<realm>
	clientKey           string   // normalized URL + realm + client, for shared stores
	oidc                *oidcClient
	loginStore          *loginStore
	CallbackURL         *url.URL
	UseAuthHeader       bool
	UserClaimName       string
	UserHeaderName      string
	IgnorePathPrefixes  []string
	RefreshBeforeExpiry time.Duration
	SessionStore        *SessionStore
}

func CreateConfig() *Config {
	return &Config{SessionCapacity: 10000}
}

func parseUrl(rawUrl string) (*url.URL, error) {
	if rawUrl == "" {
		return nil, errors.New("invalid empty url")
	}
	if !strings.Contains(rawUrl, "://") {
		rawUrl = "https://" + rawUrl
	}
	u, err := url.Parse(rawUrl)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%v is not a valid scheme", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("invalid url: missing host")
	}
	if u.User != nil {
		return nil, errors.New("invalid url: userinfo not allowed")
	}
	if strings.Contains(rawUrl, "#") {
		return nil, errors.New("invalid url: fragment not allowed")
	}
	if u.RawQuery != "" {
		return nil, errors.New("invalid url: query not allowed")
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return nil, errors.New("url must use https except on loopback")
	}
	return u, nil
}

func canonicalKeycloakURL(u *url.URL) string {
	canonical := *u
	canonical.Scheme = strings.ToLower(canonical.Scheme)
	hostname := strings.ToLower(canonical.Hostname())
	port := canonical.Port()
	if canonical.Scheme == "http" && port == "80" || canonical.Scheme == "https" && port == "443" {
		port = ""
	}
	canonical.Host = hostname
	if strings.Contains(hostname, ":") {
		canonical.Host = "[" + hostname + "]"
	}
	if port != "" {
		canonical.Host = net.JoinHostPort(hostname, port)
	}

	escapedPath := canonical.EscapedPath()
	canonical.Path = ""
	canonical.RawPath = ""
	if escapedPath != "" && escapedPath != "/" {
		normalizedPath := path.Clean(escapedPath)
		decodedPath, err := url.PathUnescape(normalizedPath)
		if err != nil {
			return ""
		}
		canonical.Path = decodedPath
		if normalizedPath != decodedPath {
			canonical.RawPath = normalizedPath
		}
	}
	return canonical.String()
}

// validateCallbackURL accepts only exact http/https schemes and, for http,
// only loopback hosts, so development can use a plain HTTP callback while any
// deployed callback must be HTTPS.
func validateCallbackURL(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, errors.New("invalid empty callback url")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("invalid callback url scheme %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("invalid callback url: missing host")
	}
	if u.Path == "" {
		return nil, errors.New("invalid callback url: missing path")
	}
	if strings.Contains(raw, "#") {
		return nil, errors.New("invalid callback url: fragment not allowed")
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return nil, errors.New("callback url must use https except on loopback")
	}
	return u, nil
}

// isLoopbackHost reports whether host resolves to a loopback address. It treats
// the reserved .localhost TLD, which statically resolves to loopback, the same
// as the bare localhost name.
func isLoopbackHost(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ensureOpenIDScope guarantees the OIDC "openid" scope is present regardless
// of any additional scopes the operator configured.
func ensureOpenIDScope(scope string) string {
	for _, field := range strings.Fields(scope) {
		if field == "openid" {
			return scope
		}
	}
	if scope == "" {
		return "openid"
	}
	return "openid " + scope
}

func parseIgnorePathPrefixes(raw string) ([]string, error) {
	if raw == "" {
		return []string{}, nil
	}
	parts := strings.Split(raw, ",")
	prefixes := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, errors.New("invalid ignore path prefix: empty entry")
		}
		if !strings.HasPrefix(part, "/") {
			return nil, fmt.Errorf("invalid ignore path prefix %q: must start with /", part)
		}
		if part != "/" {
			part = strings.TrimRight(part, "/")
			if part == "" {
				return nil, errors.New("invalid ignore path prefix: empty entry")
			}
		}
		prefixes = append(prefixes, part)
	}
	return prefixes, nil
}

// validUserHeaderName reports whether name is an RFC 7230 token usable as an
// HTTP header field name. Authorization is reserved for validated sessions.
func validUserHeaderName(name string) bool {
	if name == "" || strings.EqualFold(name, "Authorization") {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)):
		default:
			return false
		}
	}
	return true
}

func readSecretFiles(config *Config) error {
	if config.ClientIDFile != "" {
		id, err := os.ReadFile(config.ClientIDFile)
		if err != nil {
			return err
		}
		clientId := string(id)
		clientId = strings.TrimSpace(clientId)
		clientId = strings.TrimSuffix(clientId, "\n")
		config.ClientID = clientId
	}
	if config.ClientSecretFile != "" {
		secret, err := os.ReadFile(config.ClientSecretFile)
		if err != nil {
			return err
		}
		clientSecret := string(secret)
		clientSecret = strings.TrimSpace(clientSecret)
		clientSecret = strings.TrimSuffix(clientSecret, "\n")
		config.ClientSecret = clientSecret
	}
	return nil
}

func readConfigEnv(config *Config) error {
	if config.KeycloakURLEnv != "" {
		keycloakUrl := os.Getenv(config.KeycloakURLEnv)
		if keycloakUrl == "" {
			return errors.New("KeycloakURLEnv referenced but NOT set")
		}
		config.KeycloakURL = strings.TrimSpace(keycloakUrl)
	}
	if config.InsecureSkipVerifyEnv != "" {
		insecureSkipVerify := os.Getenv(config.InsecureSkipVerifyEnv)
		if insecureSkipVerify == "" {
			return errors.New("InsecureSkipVerifyEnv referenced but NOT set")
		}
		insecureSkipVerifyBool, err := strconv.ParseBool(insecureSkipVerify)
		if err != nil {
			return err
		}
		config.InsecureSkipVerify = insecureSkipVerifyBool
	}
	if config.ClientIDEnv != "" {
		clientId := os.Getenv(config.ClientIDEnv)
		if clientId == "" {
			return errors.New("ClientIDEnv referenced but NOT set")
		}
		config.ClientID = strings.TrimSpace(clientId)
	}
	if config.ClientSecretEnv != "" {
		clientSecret := os.Getenv(config.ClientSecretEnv)
		if clientSecret == "" {
			return errors.New("ClientSecretEnv referenced but NOT set")
		}
		config.ClientSecret = strings.TrimSpace(clientSecret)
	}
	if config.KeycloakRealmEnv != "" {
		keycloakRealm := os.Getenv(config.KeycloakRealmEnv)
		if keycloakRealm == "" {
			return errors.New("KeycloakRealmEnv referenced but NOT set")
		}
		config.KeycloakRealm = strings.TrimSpace(keycloakRealm)
	}
	if config.ScopeEnv != "" {
		scope := os.Getenv(config.ScopeEnv)
		if scope == "" {
			return errors.New("ScopeEnv referenced but NOT set")
		}
		config.Scope = scope //Do not trim space here as it is common to use space as a separator and should be properly escaped when encoded
	}
	if config.UseAuthHeaderEnv != "" {
		useAuthHeader, exists := os.LookupEnv(config.UseAuthHeaderEnv)
		if !exists {
			return fmt.Errorf("UseAuthHeaderEnv %q referenced but NOT set", config.UseAuthHeaderEnv)
		}
		if useAuthHeader == "" {
			return fmt.Errorf("UseAuthHeaderEnv %q is empty", config.UseAuthHeaderEnv)
		}
		useAuthHeaderBool, err := strconv.ParseBool(useAuthHeader)
		if err != nil {
			return fmt.Errorf("UseAuthHeaderEnv %q: %w", config.UseAuthHeaderEnv, err)
		}
		config.UseAuthHeader = useAuthHeaderBool
	}
	if config.IgnorePathPrefixesEnv != "" {
		ignorePathPrefixes := os.Getenv(config.IgnorePathPrefixesEnv)
		if ignorePathPrefixes == "" {
			return errors.New("IgnorePathPrefixesEnv referenced but NOT set")
		}
		config.IgnorePathPrefixes = strings.TrimSpace(ignorePathPrefixes)
	}
	if config.RefreshBeforeExpiryEnv != "" {
		refreshBeforeExpiry := os.Getenv(config.RefreshBeforeExpiryEnv)
		if refreshBeforeExpiry == "" {
			return errors.New("RefreshBeforeExpiryEnv referenced but NOT set")
		}
		config.RefreshBeforeExpiry = strings.TrimSpace(refreshBeforeExpiry)
	}
	if config.LegacySupportEnv != "" {
		legacySupport := os.Getenv(config.LegacySupportEnv)
		if legacySupport == "" {
			return errors.New("LegacySupportEnv referenced but NOT set")
		}
		legacySupportBool, err := strconv.ParseBool(legacySupport)
		if err != nil {
			return err
		}
		config.LegacySupport = legacySupportBool
	}
	return nil
}

func New(uctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	err := readSecretFiles(config)
	if err != nil {
		return nil, err
	}
	err = readConfigEnv(config)
	if err != nil {
		return nil, err
	}

	if config.ClientID == "" || config.ClientSecret == "" || config.KeycloakRealm == "" {
		return nil, errors.New("invalid configuration")
	}

	parsedURL, err := parseUrl(config.KeycloakURL)
	if err != nil {
		return nil, err
	}

	upstream := newUpstreamHTTPClient(config.InsecureSkipVerify)

	keycloakURL := parsedURL
	if config.LegacySupport && path.Base(parsedURL.Path) != "auth" {
		keycloakURL = parsedURL.JoinPath("auth")
	}

	callbackURL, err := validateCallbackURL(config.CallbackURL)
	if err != nil {
		return nil, err
	}

	sessionCapacity := config.SessionCapacity
	if sessionCapacity <= 0 {
		return nil, errors.New("invalid session capacity")
	}

	scope := ensureOpenIDScope(config.Scope)

	if config.RefreshBeforeExpiry == "" {
		config.RefreshBeforeExpiry = "30s"
	}
	refreshBeforeExpiry, err := time.ParseDuration(config.RefreshBeforeExpiry)
	if err != nil {
		return nil, fmt.Errorf("invalid RefreshBeforeExpiry %q: %w", config.RefreshBeforeExpiry, err)
	}
	if refreshBeforeExpiry < 0 {
		return nil, errors.New("RefreshBeforeExpiry must not be negative")
	}

	userClaimName := "preferred_username"
	if config.UserClaimName != "" {
		userClaimName = config.UserClaimName
	}

	userHeaderName := "X-Forwarded-User"
	if config.UserHeaderName != "" {
		userHeaderName = config.UserHeaderName
	}
	if !validUserHeaderName(userHeaderName) {
		return nil, fmt.Errorf("invalid user header name %q", userHeaderName)
	}

	ignorePathPrefixes, err := parseIgnorePathPrefixes(config.IgnorePathPrefixes)
	if err != nil {
		return nil, err
	}

	issuer := keycloakURL.JoinPath("realms", config.KeycloakRealm).String()
	clientKey := strings.Join([]string{canonicalKeycloakURL(keycloakURL), config.KeycloakRealm, config.ClientID}, "\x00")

	oidcClient, err := newOIDCClient(runtimeConfig{
		Issuer:       issuer,
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		CallbackURL:  callbackURL.String(),
		Scope:        scope,
		Upstream:     upstream,
	})
	if err != nil {
		return nil, err
	}

	sessionStore := sharedSessionStore(clientKey, sessionCapacity)
	sessionStore.SetCapacity(sessionCapacity)
	loginStore := sharedLoginStore(clientKey, callbackURL.String())

	return &keycloakAuth{
		next:                next,
		KeycloakURL:         keycloakURL,
		issuer:              issuer,
		clientKey:           clientKey,
		oidc:                oidcClient,
		loginStore:          loginStore,
		CallbackURL:         callbackURL,
		UseAuthHeader:       config.UseAuthHeader,
		UserClaimName:       userClaimName,
		UserHeaderName:      userHeaderName,
		IgnorePathPrefixes:  ignorePathPrefixes,
		RefreshBeforeExpiry: refreshBeforeExpiry,
		SessionStore:        sessionStore,
	}, nil
}
