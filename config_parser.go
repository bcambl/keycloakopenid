package keycloakopenid

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
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
	SilentRenewal       *bool  `json:"silent_renewal"`
	RefreshBeforeExpiry string `json:"refresh_before_expiry"`

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
	SilentRenewalEnv       string `json:"silent_renewal_env"`
	RefreshBeforeExpiryEnv string `json:"refresh_before_expiry_env"`
}

type keycloakAuth struct {
	next                http.Handler
	KeycloakURL         *url.URL
	InsecureSkipVerify  bool
	ClientID            string
	ClientSecret        string
	KeycloakRealm       string
	Scope               string
	UseAuthHeader       bool
	UserClaimName       string
	UserHeaderName      string
	IgnorePathPrefixes  []string
	SessionStore        *SessionStore
	SilentRenewal       bool
	RefreshBeforeExpiry time.Duration
}

type KeycloakTokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
}

type state struct {
	RedirectURL string `json:"redirect_url"`
}

func CreateConfig() *Config {
	return &Config{}
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
	if !strings.HasPrefix(u.Scheme, "http") {
		return nil, fmt.Errorf("%v is not a valid scheme", u.Scheme)
	}
	return u, nil
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
			useAuthHeader = "false"
		}
		useAuthHeader = strings.ToLower(useAuthHeader)
		config.UseAuthHeader = useAuthHeader == "true" || useAuthHeader == "1"
	}
	if config.IgnorePathPrefixesEnv != "" {
		ignorePathPrefixes := os.Getenv(config.IgnorePathPrefixesEnv)
		if ignorePathPrefixes == "" {
			return errors.New("IgnorePathPrefixesEnv referenced but NOT set")
		}
		config.IgnorePathPrefixes = strings.TrimSpace(ignorePathPrefixes)
	}
	if config.SilentRenewalEnv != "" {
		silentRenewal := os.Getenv(config.SilentRenewalEnv)
		if silentRenewal == "" {
			return errors.New("SilentRenewalEnv referenced but NOT set")
		}
		silentRenewalBool, err := strconv.ParseBool(silentRenewal)
		if err != nil {
			return err
		}
		config.SilentRenewal = &silentRenewalBool
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

	if config.ClientID == "" || config.KeycloakRealm == "" {
		return nil, errors.New("invalid configuration")
	}

	parsedURL, err := parseUrl(config.KeycloakURL)
	if err != nil {
		return nil, err
	}

	keycloakURL := parsedURL
	if config.LegacySupport {
		compatUrl, err := setKeycloakCompatURL(parsedURL, config.KeycloakRealm, config.InsecureSkipVerify)
		if err != nil {
			return nil, err
		}
		keycloakURL = compatUrl
	}

	if config.Scope == "" {
		config.Scope = "openid"
	}

	if config.RefreshBeforeExpiry == "" {
		config.RefreshBeforeExpiry = "30s"
	}
	refreshBeforeExpiry := 30 * time.Second
	silentRenewal := config.SilentRenewal == nil || *config.SilentRenewal
	if silentRenewal {
		parsed, err := time.ParseDuration(config.RefreshBeforeExpiry)
		if err != nil {
			return nil, err
		}
		refreshBeforeExpiry = parsed
	}

	useAuthHeader := false
	if config.UseAuthHeader {
		useAuthHeader = true
	}

	userClaimName := "preferred_username"
	if config.UserClaimName != "" {
		userClaimName = config.UserClaimName
	}

	userHeaderName := "X-Forwarded-User"
	if config.UserHeaderName != "" {
		userHeaderName = config.UserHeaderName
	}

	ignorePathPrefixes := []string{}
	if config.IgnorePathPrefixes != "" {
		ignorePathPrefixes = strings.Split(config.IgnorePathPrefixes, ",")
	}

	return &keycloakAuth{
		next:                next,
		KeycloakURL:         keycloakURL,
		InsecureSkipVerify:  config.InsecureSkipVerify,
		ClientID:            config.ClientID,
		ClientSecret:        config.ClientSecret,
		KeycloakRealm:       config.KeycloakRealm,
		Scope:               config.Scope,
		UseAuthHeader:       useAuthHeader,
		UserClaimName:       userClaimName,
		UserHeaderName:      userHeaderName,
		IgnorePathPrefixes:  ignorePathPrefixes,
		SessionStore:        sharedSessionStore(strings.Join([]string{keycloakURL.String(), config.KeycloakRealm, config.ClientID}, "\x00")),
		SilentRenewal:       silentRenewal,
		RefreshBeforeExpiry: refreshBeforeExpiry,
	}, nil
}

// setKeycloakCompatURL will test a couple well-known keycloak endpoints to determine if
// the current keycloak instance is the older wildfly or the newer quarkus version and
// and dynamically add /auth to the url as required.
func setKeycloakCompatURL(keycloakURL *url.URL, realm string, skipVerify bool) (*url.URL, error) {

	// default to newer quarkus by querying /realms/{realm}
	target := keycloakURL.JoinPath("realms", realm)
	fmt.Println("target: ", target.String())

	// create a new http client
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify},
		},
	}

	// make a GET request to the target URL
	resp, err := client.Get(target.String())
	if err != nil {
		return keycloakURL, err
	}
	defer resp.Body.Close()

	// check status code
	if resp.StatusCode == http.StatusOK {
		return keycloakURL, nil
	}

	// if the status code is not 200, try the old wildfly URL
	target = keycloakURL.JoinPath("auth", "realms", realm)

	// make a GET request to the target URL
	resp, err = client.Get(target.String())
	if err != nil {
		return keycloakURL, err
	}
	defer resp.Body.Close()

	// check status code
	if resp.StatusCode == http.StatusOK {
		return keycloakURL.JoinPath("auth"), nil
	}

	return keycloakURL, errors.New("could not determine Keycloak compatibility")
}
