.DEFAULT_GOAL := help

GO ?= go
GOFMT ?= gofmt
GOLANGCI_LINT ?= golangci-lint
PODMAN ?= podman
PYTHON ?= python3

VM_HOST ?=
VM_USER ?=
VM_PASS ?=
K3S_VERSION ?= v1.37.2+k3s1
K3S_DIR := dev/k3s
ANSIBLE_VENV := .venv/bin
ANSIBLE := $(ANSIBLE_VENV)/ansible
ANSIBLE_PLAYBOOK := $(ANSIBLE_VENV)/ansible-playbook

export VM_HOST VM_USER VM_PASS

MODULES := . dev/helloworld
GO_FILES := $(wildcard *.go) $(wildcard dev/helloworld/*.go)

STACK ?= keycloakopenid
STACK_NETWORK := $(STACK)_default
HELLOWORLD_IMAGE := localhost/$(STACK)_helloworld:latest
KEYCLOAK_CONTAINER := $(STACK)_keycloak_1
TRAEFIK_CONTAINER := $(STACK)_traefik_1
HELLOWORLD1_CONTAINER := $(STACK)_helloworld1_1
HELLOWORLD2_CONTAINER := $(STACK)_helloworld2_1
CONTAINERS := $(TRAEFIK_CONTAINER) $(HELLOWORLD1_CONTAINER) $(HELLOWORLD2_CONTAINER) $(KEYCLOAK_CONTAINER)

.PHONY: help tag-patch tag-minor tag-major fmt fmt-check vet lint test test-race cover tidy vendor-check check up down restart logs ps smoke demo clean require-vm-env vm-venv vm-check vm-syntax vm-up vm-demo-per-app vm-demo-shared vm-sync vm-status vm-logs vm-down vm-uninstall-k3s vm-kubeconfig

help: ## Show all available targets
	@awk 'BEGIN { FS = "## " }; /^[a-zA-Z0-9_-]+:.*## / { split($$1, target, ":"); printf "  %-18s %s\n", target[1], $$2 }' $(MAKEFILE_LIST)

tag-patch: ## Create and push the next patch tag
tag-minor: ## Create and push the next minor tag
tag-major: ## Create and push the next major tag

tag-patch tag-minor tag-major: tag-%:
	@set -e; \
	latest="$$(git tag --list 'v*.*.*' --sort=-v:refname | head -n 1)"; \
	if [ -z "$$latest" ]; then \
		printf 'No existing semantic version tags found.\n' >&2; \
		exit 1; \
	fi; \
	new="$$(printf '%s\n' "$$latest" | awk -F. -v bump="$*" '{ \
		major = substr($$1, 2) + 0; \
		minor = $$2 + 0; \
		patch = $$3 + 0; \
		if (bump == "major") { major++; minor = 0; patch = 0 } \
		if (bump == "minor") { minor++; patch = 0 } \
		if (bump == "patch") { patch++ } \
		printf "v%d.%d.%d\n", major, minor, patch; \
	}')"; \
	printf 'Creating and pushing tag %s\n' "$$new"; \
	git tag "$$new"; \
	git push origin "$$new"

fmt: ## Format Go files in both modules
	$(GOFMT) -w $(GO_FILES)

fmt-check: ## Check Go files are gofmt-formatted
	@unformatted="$$($(GOFMT) -l $(GO_FILES))"; \
	if [ -n "$$unformatted" ]; then \
		printf 'Files need gofmt:\n%s\n' "$$unformatted"; \
		exit 1; \
	fi

vet: ## Run go vet in both Go modules
	@set -e; for module in $(MODULES); do \
		printf '==> go vet (%s)\n' "$$module"; \
		(cd "$$module" && $(GO) vet ./...); \
	done

lint: fmt-check vet ## Run formatting, vet, and golangci-lint checks
	@command -v "$(GOLANGCI_LINT)" >/dev/null 2>&1 || { \
		printf 'golangci-lint was not found; install it or set GOLANGCI_LINT to its executable.\n' >&2; \
		exit 127; \
	}
	@status=0; for module in $(MODULES); do \
		printf '==> golangci-lint (%s)\n' "$$module"; \
		if ! (cd "$$module" && "$(GOLANGCI_LINT)" run); then status=1; fi; \
	done; \
	exit "$$status"

test: ## Run Go tests in both modules
	@set -e; for module in $(MODULES); do \
		printf '==> go test (%s)\n' "$$module"; \
		(cd "$$module" && $(GO) test ./...); \
	done

test-race: ## Run race-enabled Go tests in both modules
	@set -e; for module in $(MODULES); do \
		printf '==> go test -race (%s)\n' "$$module"; \
		(cd "$$module" && $(GO) test -race ./...); \
	done

cover: ## Run Go tests and report plugin-module coverage
	$(GO) test -coverprofile=coverage.out ./...
	(cd dev/helloworld && $(GO) test -cover ./...)
	$(GO) tool cover -func=coverage.out

tidy: ## Run go mod tidy in both Go modules
	@set -e; for module in $(MODULES); do \
		printf '==> go mod tidy (%s)\n' "$$module"; \
		(cd "$$module" && $(GO) mod tidy); \
	done

vendor-check: ## Verify `go mod vendor` produces no uncommitted diff
	@GOPROXY=off $(GO) mod vendor
	@git diff --quiet -- go.mod go.sum vendor || { \
		printf 'Vendored dependencies are out of date; run `go mod vendor` and commit the changes.\n' >&2; \
		exit 1; \
	}

check: fmt-check lint test vendor-check ## Run formatting, lint, test, and vendor checks

up: down ## Build and start the local Podman development stack
	$(PODMAN) build -t $(HELLOWORLD_IMAGE) dev/helloworld
	@$(PODMAN) network exists $(STACK_NETWORK) || $(PODMAN) network create $(STACK_NETWORK)
	$(PODMAN) run -d --name $(KEYCLOAK_CONTAINER) \
		--network $(STACK_NETWORK) \
		-p 127.0.0.1:8081:8081 \
		-e KC_BOOTSTRAP_ADMIN_USERNAME=demo-admin \
		-e KC_BOOTSTRAP_ADMIN_PASSWORD=demo-admin-password \
		-v "$(CURDIR)/dev/keycloak:/opt/keycloak/data/import:ro" \
		--security-opt label=disable \
		quay.io/keycloak/keycloak:26.3.5 \
		start-dev --http-host=0.0.0.0 --http-port=8081 --import-realm
	$(PODMAN) run -d --name $(TRAEFIK_CONTAINER) \
		--network host \
		-v "$(CURDIR):/plugins-local/src/github.com/bcambl/keycloakopenid:ro" \
		-v "$(CURDIR)/dev/traefik:/etc/traefik:ro" \
		--security-opt label=disable \
		traefik:v3.3.3 \
		--configFile=/etc/traefik/traefik.yml
	$(PODMAN) run -d --name $(HELLOWORLD1_CONTAINER) \
		--network $(STACK_NETWORK) \
		-p 127.0.0.1:9001:8080 \
		-e APP_NAME=helloworld1 \
		-e OTHER_APP_URL=http://helloworld2.localhost:8000 \
		$(HELLOWORLD_IMAGE)
	$(PODMAN) run -d --name $(HELLOWORLD2_CONTAINER) \
		--network $(STACK_NETWORK) \
		-p 127.0.0.1:9002:8080 \
		-e APP_NAME=helloworld2 \
		-e OTHER_APP_URL=http://helloworld1.localhost:8000 \
		$(HELLOWORLD_IMAGE)

down: ## Stop and remove the local development stack
	@for container in $(CONTAINERS); do \
		$(PODMAN) rm -f --ignore "$$container"; \
	done
	@if $(PODMAN) network exists $(STACK_NETWORK); then $(PODMAN) network rm $(STACK_NETWORK); fi

restart: ## Restart Traefik to reload plugin changes
	$(PODMAN) restart $(TRAEFIK_CONTAINER)

logs: ## Show the latest logs from the local stack
	@for container in $(CONTAINERS); do \
		if $(PODMAN) container exists "$$container"; then \
			$(PODMAN) logs --names --tail=100 "$$container"; \
		fi; \
	done

ps: ## Show local development stack service status
	$(PODMAN) ps -a --filter name=$(STACK)_ --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'

smoke: ## Run the local Keycloak and proxy end-to-end smoke test
	$(PYTHON) dev/scripts/smoke-test.py

demo: ## Start the local stack and run the end-to-end smoke test
	$(MAKE) up
	$(MAKE) smoke

clean: ## Remove generated Go coverage output
	rm -f coverage.out

require-vm-env:
	@missing=0; \
	for variable in VM_HOST VM_USER VM_PASS; do \
		case "$$variable" in \
			VM_HOST) value="$$VM_HOST" ;; \
			VM_USER) value="$$VM_USER" ;; \
			VM_PASS) value="$$VM_PASS" ;; \
		esac; \
		if [ -z "$$value" ]; then \
			printf 'Required environment variable %s is not set.\n' "$$variable" >&2; \
			missing=1; \
		fi; \
	done; \
	if [ "$$missing" -ne 0 ]; then exit 2; fi; \
	command -v sshpass >/dev/null 2>&1 || { \
		printf 'sshpass is required for vm-* targets; install it and retry.\n' >&2; \
		exit 2; \
	}

vm-venv: require-vm-env ## Create the project-local Ansible virtual environment
	$(PYTHON) -m venv .venv
	.venv/bin/python -m pip install --requirement $(K3S_DIR)/requirements.txt

vm-check: require-vm-env vm-venv ## Validate VM access with an Ansible ping
	cd $(K3S_DIR) && ../../$(ANSIBLE) all -m ping

vm-syntax: require-vm-env vm-venv ## Check Ansible playbook syntax
	cd $(K3S_DIR) && ../../$(ANSIBLE_PLAYBOOK) --syntax-check site.yml sync-plugin.yml teardown.yml
	$(ANSIBLE_VENV)/python -m unittest discover -s $(K3S_DIR)/tests

vm-up: require-vm-env vm-venv ## Install k3s and deploy the per-app demo on the Fedora VM
	cd $(K3S_DIR) && ../../$(ANSIBLE_PLAYBOOK) site.yml -e k3s_version=$(K3S_VERSION) -e demo_mode=per-app

vm-demo-per-app: require-vm-env vm-venv ## Apply per-app clients on the VM and run its smoke test
	cd $(K3S_DIR) && ../../$(ANSIBLE_PLAYBOOK) site.yml --tags demo_mode -e demo_mode=per-app
	$(PYTHON) dev/scripts/k3s-smoke-test.py --mode per-app

vm-demo-shared: require-vm-env vm-venv ## Apply the shared multi-app client on the VM and run its smoke test
	cd $(K3S_DIR) && ../../$(ANSIBLE_PLAYBOOK) site.yml --tags demo_mode -e demo_mode=shared
	$(PYTHON) dev/scripts/k3s-smoke-test.py --mode shared

vm-sync: require-vm-env vm-venv ## Sync local plugin source and restart Traefik on the VM
	cd $(K3S_DIR) && ../../$(ANSIBLE_PLAYBOOK) sync-plugin.yml

vm-status: require-vm-env vm-venv ## Show VM pods and Traefik custom resources
	cd $(K3S_DIR) && ../../$(ANSIBLE) all -m command -a 'k3s kubectl get pods --all-namespaces'
	cd $(K3S_DIR) && ../../$(ANSIBLE) all -m command -a 'k3s kubectl get ingressroutes,middlewares --all-namespaces'

vm-logs: require-vm-env vm-venv ## Show Traefik and Keycloak logs from the VM
	cd $(K3S_DIR) && ../../$(ANSIBLE) all -m command -a 'k3s kubectl logs -n kube-system deployment/traefik --tail=100'
	cd $(K3S_DIR) && ../../$(ANSIBLE) all -m command -a 'k3s kubectl logs -n demo deployment/keycloak --tail=100'

vm-down: require-vm-env vm-venv ## Remove the demo namespace and Traefik plugin config from the VM
	cd $(K3S_DIR) && ../../$(ANSIBLE_PLAYBOOK) teardown.yml

vm-uninstall-k3s: require-vm-env ## Uninstall k3s and demo files from the VM (requires CONFIRM=yes)
	@if [ "$(CONFIRM)" != "yes" ]; then \
		printf 'This removes k3s and all of its workloads from %s; re-run with CONFIRM=yes.\n' "$$VM_HOST" >&2; \
		exit 2; \
	fi
	$(MAKE) vm-venv
	cd $(K3S_DIR) && ../../$(ANSIBLE_PLAYBOOK) teardown.yml -e uninstall_k3s=true

vm-kubeconfig: require-vm-env vm-venv ## Fetch a local kubeconfig configured for VM_HOST
	cd $(K3S_DIR) && ../../$(ANSIBLE) all -m fetch -a 'src=/etc/rancher/k3s/k3s.yaml dest=$(abspath $(K3S_DIR)/.kubeconfig) flat=yes'
	$(PYTHON) -c 'import os, pathlib; path = pathlib.Path("$(K3S_DIR)/.kubeconfig"); content = path.read_text(); old = "https://127.0.0.1:6443"; assert old in content, "expected the standard local k3s API address"; path.write_text(content.replace(old, "https://" + os.environ["VM_HOST"] + ":6443"))'