# Keycloak Authentication Plugin

This Keycloak authentication plugin is a middleware for Go applications, which manages user authentication using Keycloak, an open-source identity and access management solution.

## Code Explanation

### Structs

The plugin uses several data structures:

- Config: This struct stores the configuration details of the Keycloak instance, such as the URL, client ID, and client secret.
  keycloakAuth: This struct is the main component of the plugin, storing the next HTTP handler and the configuration.
  KeycloakTokenResponse: This struct stores the response from Keycloak when a token is requested.
- state: This struct stores the URL to which the user should be redirected after successful authentication.

### Main Functions

The plugin has several main functions:

- CreateConfig(): Initializes and returns a new Config struct.
- New(): Creates a new Keycloak authentication middleware. It checks the provided configuration and returns an error if the Keycloak URL or client ID is not provided.
- ServeHTTP(): This is the main function of the middleware. It checks for an "Authorization" cookie in the request. If the cookie exists and its value starts with "Bearer ", it verifies the token. If the token is valid, it allows the request to proceed. If the token is invalid, it redirects the request to Keycloak for authentication. If the cookie does not exist, it checks for an authorization code in the request URL. If the code exists, it exchanges it for a token. If the code does not exist, it redirects the request to Keycloak for authentication.
- exchangeAuthCode(): Exchanges an authorization code for a token.
- redirectToKeycloak(): Redirects the request to Keycloak for authentication.
- verifyToken(): Verifies the validity of a token.

## How it Works

When a request is received, the middleware first checks for an "Authorization" cookie. If it exists and the token inside is valid, the request is allowed to proceed.
If the token is invalid or doesn't exist, the middleware checks for an authorization code in the request URL.
If the authorization code exists, the middleware exchanges it for a token, sets this token as a cookie, and redirects the user to their original location.
If the authorization code doesn't exist, the middleware redirects the user to Keycloak for authentication.
The user is then prompted to enter their credentials on the Keycloak login page. After successful authentication, Keycloak redirects the user back to the application with an authorization code.
The middleware then exchanges this code for a token and the process starts over.
By using this middleware, applications can easily integrate with Keycloak for user authentication without having to implement the logic themselves.

## Installation

First, enable the plugins support in your Traefik configuration file (traefik.yml or traefik.toml):

```yaml
experimental:
  plugins:
    keycloakopenid:
      moduleName: "github.com/bcambl/keycloakopenid"
      version: "v0.1.38"
```

Usage
Add the plugin's specific configuration to your Traefik routers:

```yaml
http:
  middlewares:
    my-keycloakopenid:
      plugin:
        keycloakopenid:
          KeycloakURL: "my-keycloak-url.com" # <- Also supports complete URL, e.g. https://my-keycloak-url.com/auth
          ClientID: "<CLIENT_ID"
          ClientSecret: "<CLIENT_SECRET"
          KeycloakRealm: "<REALM"
          Scope: "<Scope [space deliminated] (default: 'openid', example: 'openid profile email')"
          TokenCookieName: "<TOKEN_COOKIE_NAME (default: 'AUTH_TOKEN')"
          UseAuthHeader: "<true|false (default: false)"
          SilentRenewal: "<true|false (default: true)>"
          RefreshBeforeExpiry: "<duration (default: '30s', example: '45s')>"
          IgnorePathPrefixes: "/api,/favicon.ico [comma deliminated] (optional)"
```

Alternatively, ClientID and ClientSecret can be read from a file to support Docker Secrets and Kubernetes Secrets:

```yaml
http:
  middlewares:
    my-keycloakopenid:
      plugin:
        keycloakopenid:
          KeycloakURL: "https://my-keycloak-url.com/auth"
          ClientIDFile: "/run/secrets/clientId.txt"
          ClientSecretFile: "/run/secrets/clientSecret.txt"
          KeycloakRealm: "<REALM"
          Scope: "<SCOPE [space deliminated] (default: 'openid', example: 'openid profile email')"
          TokenCookieName: "<TOKEN_COOKIE_NAME (default: 'AUTH_TOKEN')"
          UseAuthHeader: "<true|false (default: false)"
```

Last but not least, each configuration can be read from environment file to support some Kubernetes configurations:

```yaml
http:
  middlewares:
    my-keycloakopenid:
      plugin:
        keycloakopenid:
          KeycloakURLEnv: "MY_KEYCLOAK_URL"
          ClientIDEnv: "MY_KEYCLOAK_CLIENT_ID"
          ClientSecretEnv: "MY_KEYCLOAK_CLIENT_SECRET"
          KeycloakRealmEnv: "MY_KEYCLOAK_REALM"
          ScopeEnv: "SCOPE [space deliminated] (default: 'openid', example: 'openid profile email')"
          TokenCookieNameEnv: "TOKEN_COOKIE_NAME (default: 'AUTH_TOKEN')"
          UseAuthHeaderEnv: "USE_AUTH_HEADER (default: false)"
          SilentRenewalEnv: "SILENT_RENEWAL (default: true)"
          RefreshBeforeExpiryEnv: "REFRESH_BEFORE_EXPIRY (default: '30s')"
```

This plugin also sets a header with a claim from Keycloak, as it has become reasonably common. Claim name and header name can be modified.  
The default claim is <code>preferred_username</code>, the default header name is <code>X-Forwarded-User</code> :

```yaml
http:
  middlewares:
    my-keycloakopenid:
      plugin:
        keycloakopenid:
          KeycloakURL: "my-keycloak-url.com" # <- Also supports complete URL, e.g. https://my-keycloak-url.com/auth
          ClientID: "<CLIENT_ID"
          ClientSecret: "<CLIENT_SECRET"
          KeycloakRealm: "<REALM"
          Scope: "<SCOPE [space deliminated] (default: 'openid', example: 'openid profile email')"
          TokenCookieName: "TOKEN_COOKIE_NAME (default: "AUTH_TOKEN)"
          UseAuthHeader: "true|false (default: false)"
          UserClaimName: "my-uncommon-claim"
          UserHeaderName: "X-Custom-Header"
```

## Silent renewal

Silent renewal is on by default. The plugin keeps a user's session alive for as long as Keycloak allows, without any user interruption:

- After the Keycloak callback, the session stores the access token, the refresh token, and the access token expiry.
- On each request the access token is introspected as usual. When it is within `RefreshBeforeExpiry` of its expiry, or already inactive, the plugin renews it with the refresh-token grant and continues the request with the new token. No redirect happens.
- Renewals are serialized per session and rotated refresh tokens are stored, so concurrent requests are safe.
- Only when Keycloak refuses the refresh (`invalid_grant`), meaning the Keycloak session is over, does the session end: browser navigation is redirected to the Keycloak login with a 303, and fetch/XHR requests receive a 401 with `{"error":"authentication_required"}` and no redirect, so the application can reload the current page in the same tab.
- A Keycloak outage is never treated as a session end: introspection or renewal transport failures answer 502 and leave the session intact. A renewal failure while the current access token is still active lets the request proceed with that token.
- The hard-coded one-hour session lifetime is not used in this mode; Keycloak's SSO and client session settings decide how long a user stays logged in.

Requirements and limitations:

- The Keycloak token response must contain a `refresh_token` (the default for the standard flow with confidential clients). If it is missing, the callback fails with an error so the misconfiguration is visible.
- Sessions stay in memory per plugin instance. A Traefik restart means users sign in again. Run a single Traefik instance or use sticky sessions; multiple non-sticky replicas would race refresh-token rotation and force repeated logins.
- With `SilentRenewal: false`, the legacy behavior is used instead: one-hour session lifetime, introspection per request, and 307 redirects. Use this opt-out if you want the old behavior, for example to force periodic re-authentication.

## Local development

For a complete Podman-based development stack with Keycloak, two protected example apps, Makefile targets, and an end-to-end smoke test, see [dev/README.md](dev/README.md). Run `make help` from the repository root to list development and test targets.

To demonstrate several apps behind one host at different paths (`/helloworld1`, `/helloworld2`) on k3s, see [dev/k3s/README.md](dev/k3s/README.md). It sets up an existing Fedora VM with `make vm-up` and compares per-app clients with one shared client.
