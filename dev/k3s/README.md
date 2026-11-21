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

The plugin always issues a single cookie named `SessionID` with `Path=/`. It stores sessions in memory, shared by every plugin instance that uses the same Keycloak client. Traefik creates a separate plugin instance for **each router** that uses a middleware, but instances configured with the same Keycloak URL, realm, and client ID see the same sessions. Together, these facts determine how path-based apps behave.

### Per-app clients (`make vm-demo-per-app`)

Each path has its own Keycloak client (`helloworld1`, `helloworld2`), its own plugin middleware and its own router.

```
websecure ─ /helloworld1 → helloworld1-auth → strip /helloworld1 → helloworld1
          └ /helloworld2 → helloworld2-auth → strip /helloworld2 → helloworld2
```

Because both apps share one host, the `SessionID` cookie that helloworld2 issues **replaces** helloworld1's, and the other way round. Each switch between apps sends the browser through Keycloak again. Keycloak's own SSO session makes this a silent redirect without a password, but every switch costs an extra round trip, and a POST body sent across the switch is lost. The smoke test asserts this collision explicitly:

```
COLLISION: returning to helloworld1 with helloworld2's SessionID forces another Keycloak round-trip
```

Host-based routing, as in the local Podman stack, does not have this problem, because each host keeps its own cookie.

### Shared multi-app client (`make vm-demo-shared`)

One Keycloak client (`helloworld-shared`, with redirect URIs for both paths) and **one** plugin instance protect both paths. Two routers sharing one Middleware would also share sessions, because both instances use the same client. This demo instead has one router authenticate every app path and hand the request to a second, cluster-internal Traefik entrypoint. Per-path routers there strip the prefix and pick the backend:

```
websecure ─ /helloworld1 || /helloworld2 → shared-auth → traefik-internal:8001 (ClusterIP only)
internal  ─ /helloworld1 → strip /helloworld1 → helloworld1
          └ /helloworld2 → strip /helloworld2 → helloworld2
```

After one login, both paths accept the same `SessionID` with no further Keycloak redirects. `X-Forwarded-User` and `Authorization` pass through the internal hop unchanged. The `internal` entrypoint is exposed only on the `traefik-internal` ClusterIP service, never on the VM's public ports. Any pod in the cluster could still reach it and forge those headers, so a production setup should restrict it with a NetworkPolicy.

### Details that apply to both modes

- The auth middleware runs **before** `StripPrefix`. The plugin builds the `redirect_uri` from the request URI, so the prefix must still be present. The smoke test checks that the redirect URI keeps `/helloworldN/`.
- `/helloworldN/healthz` bypasses authentication through `IgnorePathPrefixes: /favicon.ico,/healthz`. The plugin matches these entries with `strings.Contains`, so any path that *contains* `/healthz` skips authentication. Keep that in mind before copying this configuration.
- Sessions are held in memory in the Traefik pod. They are lost when Traefik restarts, for example after `make vm-sync`, and they would break with more than one Traefik replica. k3s runs one replica by default.

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
- **The Traefik chart rejects the values.** `localPlugins` with `type: hostPath` and `service.additionalServices` require the Traefik chart bundled with recent k3s releases, so keep `K3S_VERSION` at the pinned default or newer. The rendered values are in `/var/lib/rancher/k3s/server/manifests/traefik-config.yaml` on the VM. The `helm-install-traefik` job logs in `kube-system` show why they were rejected.
- **The browser loops back to Keycloak.** Clear cookies for `$VM_HOST`. In per-app mode a redirect on every app switch is expected, as described above.
