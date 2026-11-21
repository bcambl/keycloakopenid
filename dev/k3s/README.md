# Path-based demo on k3s

This demo turns an existing Fedora VM into a single-node k3s cluster. There, the plugin protects two apps that share **one host at different paths**:

| URL | What |
|---|---|
| `https://$VM_HOST/helloworld1/` | helloworld1, protected by the plugin |
| `https://$VM_HOST/helloworld2/` | helloworld2, protected by the plugin |
| `https://$VM_HOST/auth/` | Keycloak (realm `demo`), admin `demo-admin` / `demo-admin-password` |

The k3s Traefik loads the plugin from **your checkout**, so you can test uncommitted plugin changes. Everything is driven from the repository root with `make vm-*` targets. Ansible connects over SSH, runs inside a project-local `.venv`, and nothing is installed globally on your machine.

This is a demo environment. It uses a self-signed certificate, fixed demo secrets and passwords, and `InsecureSkipVerify` between the plugin and Keycloak. Use a disposable VM that is not exposed to an untrusted network.

## Prerequisites

On your machine:

- Python 3.12–3.14 (with the `venv` module) and `make`; the pinned `ansible-core` 2.20 requires Python 3.12–3.14 on the controller.
- `sshpass`, because Ansible uses it for password-based SSH (`sudo dnf install sshpass`, `sudo apt install sshpass` or `brew install hudochenkov/sshpass/sshpass`).
- Network access to the VM on ports 22, 443 and 6443 (6443 is only needed for `make vm-kubeconfig`).

On the VM:

- A recent Fedora Server or Cloud install with internet access, which is needed to fetch k3s, container images and Go modules.
- A user that can log in over SSH with a password and run `sudo` with that same password.
- At least 2 CPUs and 4 GB RAM, because Keycloak and the image build are the heaviest parts.

## Configure

All `vm-*` targets require these three environment variables, and they all fail early with a clear message if one is missing or `sshpass` is not installed:

```sh
export VM_HOST=192.168.122.50   # IP or DNS name the browser will use
export VM_USER=username
read -rs VM_PASS && export VM_PASS   # avoids putting the password in shell history
```

The password is only read through Ansible's environment lookup in `dev/k3s/inventory.yml`. It never appears on a command line and is never printed. SSH accepts a new host key the first time (`StrictHostKeyChecking=accept-new`) and refuses a changed one afterwards.

Other variables can be overridden as well, for example `make vm-up K3S_VERSION=v1.36.6+k3s1`, or `PYTHON=python3.12`.

## Run the demo

```sh
make vm-check          # create .venv, install ansible-core and ping the VM
make vm-up             # install k3s and deploy everything, ending in per-app mode
make vm-demo-per-app   # (re)apply per-app mode and run its smoke test
make vm-demo-shared    # switch to shared mode and run its smoke test
```

You can re-run `make vm-up` safely. The first run takes several minutes. It installs packages, k3s and Keycloak, and builds the helloworld image on the VM, so there is no CPU-architecture mismatch with your machine. The demo targets only re-render the routing layer, so switching modes takes seconds.

### Browser walkthrough

1. Open `https://$VM_HOST/helloworld1/`. Accept the self-signed certificate warning once for this host.
2. The plugin sends you to Keycloak at `https://$VM_HOST/auth/...`. Sign in as `alice` / `alice-password` or `bob` / `bob-password`.
3. helloworld1 shows the signed-in user (`X-Forwarded-User`), whether a bearer token was forwarded, and the decoded token claims.
4. Follow the link to helloworld2. You get in without a password in both modes. In per-app mode you are quietly sent through Keycloak first, as explained below.

## The two modes

The plugin issues one host-only `__Host-` session cookie per client, whose name is derived from the normalized Keycloak URL, realm, and client ID. Sessions are held in process memory, shared by every middleware instance configured with the same client. Traefik creates a separate plugin instance for **each router**, but instances that share a client share one session store and one cookie name. Together, these facts determine how path-based apps behave.

### Per-app clients (`make vm-demo-per-app`)

Each path has its own Keycloak client (`helloworld1`, `helloworld2`), its own middleware and its own router.

```
websecure ─ /helloworld1 → helloworld1-auth → strip /helloworld1 → helloworld1
          └ /helloworld2 → helloworld2-auth → strip /helloworld2 → helloworld2
```

The two clients issue two different `__Host-` cookies, so they do not overwrite each other: a browser holds both, and each path keeps its own session independently. Switching apps does not force another Keycloak round trip. Keycloak's own SSO session makes the first visit to each app a silent redirect without a password. The smoke test asserts the isolation explicitly, including that helloworld2's cookie is unknown to helloworld1:

```
helloworld2 completes SSO without a password and issues its own __Host- cookie
helloworld1's session survives helloworld2's login (distinct-client cookie isolation)
```

Host-based routing, as in the local Podman stack, behaves the same way, because each host keeps its own client and cookie.

### Shared multi-app client (`make vm-demo-shared`)

One Keycloak client (`helloworld-shared`, with a single redirect URI for its callback) protects both paths. Two routers each reference their own middleware, both configured with the same client, and a third route serves the fixed callback:

```
websecure ─ /helloworld1 → helloworld1-shared-auth → strip /helloworld1 → helloworld1
          └ /helloworld2 → helloworld2-shared-auth → strip /helloworld2 → helloworld2
          └ /callback    → helloworld1-shared-auth (intercepted)
```

Traefik creates a plugin instance per middleware, so the two app routers are separate plugin instances. Because both middlewares use the same Keycloak client, they still share one process-wide session store and one `__Host-` cookie. After one login, both paths accept the same cookie with no further Keycloak redirects; the smoke test logs in through helloworld1's middleware and then authenticates helloworld2 with the resulting cookie, proving the store is shared across instances.

### Details that apply to both modes

- The auth middleware runs **before** `StripPrefix`. The plugin sends a fixed `CallbackURL` to Keycloak as `redirect_uri` regardless of the requested path, and restores the original path after the callback. The smoke test checks that the redirect URI is the exact registered callback and that the browser returns to the original `/helloworldN/protected` path.
- `/helloworldN/healthz` bypasses authentication through `IgnorePathPrefixes`, which matches by path segment: `/healthz` matches `/healthz` and `/healthz/...`, not every path that merely contains the text.
- The plugin strips incoming `X-Forwarded-User` and `Authorization` on every request, so a client cannot spoof them. The smoke test sends hostile values on protected and ignored paths and checks they are removed.
- Sessions are held in memory in the Traefik pod and are lost when Traefik restarts, for example after `make vm-sync`. Exactly one Traefik replica is supported; k3s runs one by default.

## Develop the plugin

Edit the plugin in your checkout, then push the source to the VM's Traefik:

```sh
make vm-sync
```

This copies the plugin's `*.go`, `go.mod` and `.traefik.yml` to `/opt/keycloakopenid/src/github.com/bcambl/keycloakopenid` on the VM. The k3s Traefik chart mounts that directory as a local plugin (`experimental.localPlugins` with `type: hostPath`). The target then restarts Traefik so it reloads the interpreted plugin. Run `make vm-demo-per-app` or `make vm-demo-shared` afterwards to re-test.

## All VM targets

| Target | Purpose |
|---|---|
| `vm-venv` | Create `.venv` and install the pinned `ansible-core` from `dev/k3s/requirements.txt` |
| `vm-check` | Ping the VM through Ansible |
| `vm-syntax` | Syntax-check all playbooks |
| `vm-up` | Install k3s and deploy everything, ending in per-app mode |
| `vm-demo-per-app` | Apply per-app mode and run `dev/scripts/k3s-smoke-test.py --mode per-app` |
| `vm-demo-shared` | Apply shared mode and run `dev/scripts/k3s-smoke-test.py --mode shared` |
| `vm-sync` | Push local plugin source and restart Traefik |
| `vm-status` | List pods, IngressRoutes and Middlewares |
| `vm-logs` | Show recent Traefik and Keycloak logs |
| `vm-kubeconfig` | Write `dev/k3s/.kubeconfig` (git-ignored) pointing at `https://$VM_HOST:6443`, for use with `KUBECONFIG=dev/k3s/.kubeconfig kubectl ...` |
| `vm-down` | Delete the `demo` namespace, the Traefik plugin configuration and `/opt/keycloakopenid` |
| `vm-uninstall-k3s` | Run the k3s uninstall script and remove the demo files and image; requires `CONFIRM=yes` |

`vm-uninstall-k3s` does not remove the firewalld rules (ports 80, 443 and 6443, plus the trusted sources 10.42.0.0/16 and 10.43.0.0/16) or the installed `podman` and `openssl` packages. Other services on the VM may rely on them.

## Layout

```
dev/k3s/
  ansible.cfg, inventory.yml, requirements.txt
  group_vars/all.yml       # versions, paths, clients and apps
  site.yml                 # fedora_prep, k3s, plugin, tls, images, keycloak, apps, demo_mode
  sync-plugin.yml          # plugin role and Traefik restart
  teardown.yml             # vm-down and vm-uninstall-k3s
  tasks/apply-manifest.yml # server-side dry run, then kubectl apply
  roles/*/tasks, roles/*/templates
dev/scripts/k3s-smoke-test.py
```

Rendered manifests are kept on the VM in `/opt/keycloakopenid/manifests`. Every demo resource is labelled `app.kubernetes.io/part-of=keycloakopenid-demo`. Routing resources also carry `demo-mode=per-app|shared`, and switching modes deletes the other mode's resources.

## Troubleshooting

- **`vm-check` fails to connect.** Check that you can reach `ssh $VM_USER@$VM_HOST` with the password and that password authentication is enabled in the VM's `sshd`. If the VM was rebuilt with the same address, remove its stale entry from `~/.ssh/known_hosts`.
- **`sudo` fails.** The VM user must be able to run `sudo` with `VM_PASS`.
- **Ansible cannot import `libdnf5` on Fedora.** The playbook uses `ansible-core` 2.20's DNF 5 module, which automatically installs the missing `python3-libdnf5` module dependency and retries with the system interpreter. Check that the VM can reach its Fedora repositories; Fedora systems using DNF 4 continue through the DNF 4 module instead.
- **The smoke test times out waiting for the routes.** Run `make vm-status` and `make vm-logs`. Keycloak can take a few minutes on its first start. A plugin load error appears in the Traefik log.
- **The Keycloak callback fails with a token-exchange or connection error.** Traefik itself calls `https://$VM_HOST/auth` to exchange the code and introspect tokens. When `VM_HOST` is an IP address, the pod reaches it through the k3s service load balancer. When it is a DNS name, the playbook adds a Traefik `hostAliases` entry that maps it to the VM's default IPv4 address. If the VM has several interfaces, make sure that address is reachable.
- **Pods cannot reach each other or DNS.** The playbook adds the pod (10.42.0.0/16) and service (10.43.0.0/16) networks to firewalld's trusted zone. If firewalld was reconfigured afterwards, re-run `make vm-up`.
- **The Traefik chart rejects the values.** `localPlugins` with `type: hostPath` requires the Traefik chart bundled with recent k3s releases, so keep `K3S_VERSION` at the pinned default or newer. The rendered values are in `/var/lib/rancher/k3s/server/manifests/traefik-config.yaml` on the VM. The `helm-install-traefik` job logs in `kube-system` show why they were rejected.
- **The browser loops back to Keycloak.** Clear cookies for `$VM_HOST`, then sign in again.
