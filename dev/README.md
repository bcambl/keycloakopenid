# Local development stack

This stack runs Keycloak, Traefik with the plugin loaded from this checkout, and two small protected Go apps. The example uses HTTP and demo-only credentials; do not expose it to an untrusted network or reuse these credentials.

## Prerequisites

- Podman.
- Internet access the first time you start the stack, to pull the container images.
- Python 3 for the standard-library smoke test.

## Start

From the repository root, build and start the services with the Makefile:

```sh
make up
```

Run `make help` to list all available development, Go check, and stack-management targets. The stack targets use native Podman commands; no Compose provider is required.

Keycloak imports `dev/keycloak/demo-realm.json` when its data directory is empty. After changing realm settings, recreate the Keycloak container so the realm is imported again (`make down && make demo`); the smoke test verifies the running realm's access-token lifetime and reports an actionable error when a pre-existing container still carries the old settings. Wait for Keycloak and Traefik to finish starting before opening the apps:

- [helloworld1](http://helloworld1.localhost:8000)
- [helloworld2](http://helloworld2.localhost:8000)
- [Keycloak admin console](http://127.0.0.1:8081/admin/) — `demo-admin` / `demo-admin-password`
- [Traefik dashboard](http://127.0.0.1:8090/dashboard/)

Sign in to either app with `alice` / `alice-password` or `bob` / `bob-password`. After signing in once, follow the link to the other app to see Keycloak single sign-on. Each app has its own client, so each gets its own host-only `__Host-` session cookie and its own per-client store. `*.localhost` maps to the local machine in modern browsers, so the Secure session cookie can be used on these HTTP loopback origins.

## Test

Run the end-to-end flow, including login, the fixed callback and return-path restoration, the user and bearer headers, SSO to the second app, header sanitization on protected and ignored paths, invalid-session rejection, and the ignored health path:

```sh
make smoke
```

The smoke test also verifies the token lifecycle. The demo realm issues 10-second access tokens and the middleware refreshes 2 seconds before expiry. After an initial protected read, the test waits 11 seconds, requires the same plugin session to be accepted, and requires a changed access-token `jti` in the decoded claims, proving a real renewal. It then obtains a master-realm administrator token through `admin-cli`, finds Alice, revokes every Keycloak session through the Admin REST API, and requires the next protected request with the old plugin cookie to redirect to login and expire the session cookie. Revocation ends the browser's Keycloak SSO session, so this check runs last. The administrator credentials and endpoints are for the demo environment only.

The test uses Python's standard library and does not require external packages. Run the Go checks for both modules with:

```sh
make fmt-check vet test test-race cover
```

`make lint` also runs `golangci-lint` and requires it to be installed; set `GOLANGCI_LINT` to its executable if it is not on `PATH`. `make check` combines formatting, lint, and standard tests.

## Develop the plugin

Traefik loads the plugin source from the repository bind mount. After changing plugin code, restart Traefik so it reloads the interpreted plugin:

```sh
make restart
```

Traefik's routes and plugin settings are in `dev/traefik/dynamic.yml`; its entrypoints and local-plugin setup are in `dev/traefik/traefik.yml`. Keycloak's clients and example users are in `dev/keycloak/demo-realm.json`. The apps are deliberately small and live in their own Go module under `dev/helloworld` so they do not affect the plugin module or Traefik plugin loader.

## Path-based demo on k3s

This stack routes each app by host name. For the common Kubernetes layout where several apps share one host and differ only by path, use the k3s demo in [k3s/README.md](k3s/README.md). It configures an existing Fedora VM from `VM_HOST`, `VM_USER` and `VM_PASS` with `make vm-up`, then `make vm-demo-per-app` and `make vm-demo-shared` show and test the two client layouts.

## Stop and troubleshoot

Stop and remove the containers with:

```sh
make down
```

Keycloak's imported realm is not persisted across container removal. If a browser has an old session, sign out or clear cookies for the two `*.localhost` apps and `127.0.0.1:8081` before retrying. Check startup output with `make logs`. The services use loopback ports 8000, 8081, 8090, 9001, and 9002; if those ports are already in use, update the corresponding bindings and URLs in the `Makefile`, `dev/traefik/traefik.yml`, `dev/traefik/dynamic.yml`, and the realm redirect URIs.

This environment demonstrates the middleware on an isolated loopback stack, not production hardening. The plugin strips incoming `X-Forwarded-User` and `Authorization` on every request and issues a host-only `__Host-` session cookie; sessions are process-local, so a single Traefik instance is required and a restart signs everyone out. The example app only decodes token claims for display and does not validate them or enforce authorization; it must not be used as an authorization example.