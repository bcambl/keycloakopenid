# Keycloak Authentication Plugin

This Traefik middleware authenticates browser requests against Keycloak using the OpenID Connect authorization-code flow with S256 PKCE. It validates the returned ID token, keeps the session in a bounded in-memory LRU store, and forwards the authenticated user to the protected application.

The plugin is a rewrite of the earlier keycloakopenid middleware. The flow is now a standard confidential-client authorization-code flow: state and nonce, PKCE, validated ID-token claims, a host-only `__Host-` session cookie, header sanitization, and process-local session storage.

## How it works

1. A request without a valid session is redirected (303) to Keycloak's authorization endpoint. The plugin sends a random `state`, a `nonce`, and an S256 PKCE `code_challenge`.
2. Keycloak authenticates the user and redirects back to the plugin's fixed callback with an authorization `code` and `state`.
3. The plugin exchanges the code, verifies the `state` and `nonce`, validates the ID token, and stores the session.
4. A host-only `__Host-` session cookie is issued, and the browser is redirected back to the original path.
5. On later requests the plugin introspects the access token, renews it with the refresh token when it is within `RefreshBeforeExpiry` of expiry, and forwards the request.

Only navigation requests (a browser `GET` with an `Accept: text/html`) are redirected to Keycloak. API and `fetch`/XHR requests receive `401 {"error":"authentication_required"}` with no redirect, so a single-page app can reload the current page in the same tab.

## Configuration

Minimum configuration:

```yaml
http:
  middlewares:
    my-keycloakopenid:
      plugin:
        keycloakopenid:
          KeycloakURL: "https://my-keycloak-url.com"
          ClientID: "<CLIENT_ID>"
          ClientSecret: "<CLIENT_SECRET>"
          KeycloakRealm: "<REALM>"
          CallbackURL: "https://my-app.example.com/callback"
```

`ClientID` and `ClientSecret` can also be read from files (Docker or Kubernetes secrets):

```yaml
          ClientIDFile: "/run/secrets/clientId.txt"
          ClientSecretFile: "/run/secrets/clientSecret.txt"
```

Or from environment variables:

```yaml
          KeycloakURLEnv: "MY_KEYCLOAK_URL"
          ClientIDEnv: "MY_KEYCLOAK_CLIENT_ID"
          ClientSecretEnv: "MY_KEYCLOAK_CLIENT_SECRET"
          KeycloakRealmEnv: "MY_KEYCLOAK_REALM"
```

### Options

| Option | Default | Description |
|---|---|---|
| `KeycloakURL` | - | Keycloak base URL. A complete URL or a bare host is accepted. Required. |
| `ClientID` | - | OIDC client ID. Required. |
| `ClientSecret` | - | OIDC client secret. Required for the confidential-client code exchange, refresh, and introspection. |
| `KeycloakRealm` | - | Keycloak realm. Required. |
| `CallbackURL` | - | Fixed callback URL the browser returns to. Must be registered exactly as a redirect URI on the Keycloak client. Required. |
| `Scope` | `openid` | Space-delimited scopes. `openid` is always added. |
| `SessionCapacity` | `10000` | Maximum number of sessions held per configured client. Least-recently-used sessions are evicted beyond this bound. |
| `UseAuthHeader` | `false` | Also set the bearer access token in the `Authorization` header. |
| `UserClaimName` | `preferred_username` | ID-token claim forwarded as the user identity. |
| `UserHeaderName` | `X-Forwarded-User` | Header the user identity is written to. Must be a valid RFC 7230 header field name and must not be `Authorization`. |
| `IgnorePathPrefixes` | none | Comma-delimited path prefixes that bypass authentication. Matched by path segment, not substring. Trailing slashes are removed, so `/api/` behaves as `/api`. |
| `LegacySupport` | `false` | Probe for an older Keycloak instance that serves realms under `/auth`. |
| `RefreshBeforeExpiry` | `30s` | How close to access-token expiry a session is renewed. Must not be negative. |
| `InsecureSkipVerify` | `false` | Skip TLS verification of the Keycloak connection. For development only. |

`KeycloakURL`, `InsecureSkipVerify`, `ClientID`, `ClientSecret`, `KeycloakRealm`, `Scope`, `UseAuthHeader`, `IgnorePathPrefixes`, `LegacySupport`, and `RefreshBeforeExpiry` each also accept an `...Env` variant. `CallbackURL` and `SessionCapacity` are set directly only.

Every referenced environment variable must be set and non-empty. Boolean variables parse with Go's boolean syntax (`true`, `false`, `1`, `0`, and their variants); a missing, empty, or malformed value is a configuration error. Environment values take precedence over directly configured values, so a valid `UseAuthHeaderEnv: "false"` overrides `UseAuthHeader: true`.

Warning: an ignore prefix of `/` matches every valid absolute path and therefore disables authentication for every request routed through that middleware. Use it only on a router that must remain fully public.

### CallbackURL registration

`CallbackURL` is fixed and must be registered verbatim in the Keycloak client's `Valid redirect URIs` alongside any `Web origins`. The plugin always sends this exact URL as `redirect_uri`, regardless of the path the user requested, and restores the original path after the callback. It accepts `http` only for loopback hosts (`localhost`, `*.localhost`, and loopback IPs); any deployed callback must be `https`.

### ID-token requirements

The plugin validates the ID token returned by Keycloak: its signature, issuer, audience, authorized party (`azp` when the token has multiple audiences), required expiry and issued-at (`iat`) claims, and access-token hash (`at_hash`), plus the `nonce` echoed from the login. The token response must include an `access_token`, a `refresh_token`, and a positive `expires_in` lifetime. The claim named by `UserClaimName` (default `preferred_username`) must be present and a non-empty string; otherwise the plugin fails closed and does not call the next handler. A refreshed ID token must retain the original subject and audience set. Its nonce may be omitted, but must match the original login nonce when present.

### Header handling

The plugin strips the configured user header (default `X-Forwarded-User`) and any incoming `Authorization` from every request, on protected and ignored paths alike, before the request is routed. Only a validated session reintroduces them: the user header always, and the bearer token when `UseAuthHeader` is set. Downstream applications can therefore trust these headers only behind this middleware.

## Sessions and storage

Sessions are held in memory, inside the Traefik process. They are keyed by the normalized Keycloak URL, realm, and client ID, so every middleware instance configured with the same client shares one store and one `__Host-` cookie.

- Exactly one Traefik replica is supported. Sessions are process-local and never shared between replicas or persisted.
- A Traefik restart or replica replacement loses every session; users sign in again.
- Each per-client store is process-lifetime state, bounded by `SessionCapacity` with least-recently-used eviction.
- A session ends when Keycloak refuses a refresh (`invalid_grant`); navigation is redirected to Keycloak and API requests receive `401`.
- Introspection failures answer `502` and leave the session intact. A renewal failure for an active token may let the request proceed with its current access token. A renewal outage for an inactive token, where renewal is forced, answers `502`. Neither outcome deletes the stored session.

## Authorization is the application's job

This middleware authenticates and identifies the user. It does not authorize. `X-Forwarded-User` is a trusted-proxy convention, not an OpenID Connect standard, and carries no proof of roles or groups. There is no role or group authorization feature. A downstream application must enforce its own authorization and must not trust these headers from any path that bypasses this middleware.

## Migration from earlier versions

- Upgrading invalidates sessions issued by earlier versions, so users must sign in again. Incoming identity headers and `Authorization` are stripped before routing, including on ignored paths.
- `TokenCookieName` / `AUTH_TOKEN` are removed. The plugin issues one host-only `__Host-` session cookie whose name is derived from the client; it is not configurable.
- The authorization-cookie behavior is removed. `UseAuthHeader` controls whether the bearer token is forwarded in the `Authorization` header.
- The client-credentials grant is removed. Authentication always uses the authorization-code flow.
- `SilentRenewal` and the one-hour legacy session are removed. The plugin always renews with the refresh token as described above, and uses 303 redirects, never 307.
- `IgnorePathPrefixes` now matches by path segment (`/healthz` matches `/healthz` and `/healthz/...`), not by substring. Trailing slashes are removed, and `/` disables authentication for every path on the router.
- `CallbackURL` is now required and must be registered on the Keycloak client. Existing deployments must add it and update their client redirect URIs.
- `LegacySupport` no longer changes session behavior; it only probes for an older Keycloak `/auth` prefix. Remove it unless you target such an instance.

## Plugin dependencies

Traefik runs this plugin through Yaegi, which resolves the plugin's Go dependencies from the source that ships with the plugin rather than from a remote module proxy. The dependencies declared in `go.mod` must therefore remain vendored under `vendor/`, which is committed alongside the plugin source.

After adding, removing, or updating a dependency, run `go mod tidy && go mod vendor` and commit the resulting `go.mod`, `go.sum`, and `vendor/` changes together. `make check` verifies that the vendored dependencies still match `go.mod`.

## Local development

For a complete Podman-based development stack with Keycloak, two protected example apps, Makefile targets, and an end-to-end smoke test, see [dev/README.md](dev/README.md). Run `make help` from the repository root to list development and test targets.

To demonstrate several apps behind one host at different paths (`/helloworld1`, `/helloworld2`) on k3s, see [dev/k3s/README.md](dev/k3s/README.md). It sets up an existing Fedora VM with `make vm-up` and compares per-app clients with one shared client.
