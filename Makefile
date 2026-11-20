.DEFAULT_GOAL := help

GO ?= go
GOFMT ?= gofmt
GOLANGCI_LINT ?= golangci-lint
PYTHON ?= python3
COMPOSE ?= podman compose -f podman-compose.yml

MODULES := . dev/helloworld
GO_FILES := $(wildcard *.go) $(wildcard dev/helloworld/*.go)

.PHONY: help fmt fmt-check vet lint test test-race cover tidy check up down restart logs ps smoke demo clean

help: ## Show all available targets
	@awk 'BEGIN { FS = "## " }; /^[a-zA-Z0-9_-]+:.*## / { split($$1, target, ":"); printf "  %-12s %s\n", target[1], $$2 }' $(MAKEFILE_LIST)

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

check: fmt-check lint test ## Run formatting, lint, and test checks

up: ## Build and start the local Podman development stack
	$(COMPOSE) up --build -d

down: ## Stop and remove the local development stack
	$(COMPOSE) down

restart: ## Restart Traefik to reload plugin changes
	$(COMPOSE) restart traefik

logs: ## Show the latest logs from the local stack
	$(COMPOSE) logs --tail=100

ps: ## Show local development stack service status
	$(COMPOSE) ps

smoke: ## Run the local Keycloak and proxy end-to-end smoke test
	$(PYTHON) dev/scripts/smoke-test.py

demo: ## Start the local stack and run the end-to-end smoke test
	$(MAKE) up
	$(MAKE) smoke

clean: ## Remove generated Go coverage output
	rm -f coverage.out