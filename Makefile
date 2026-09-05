# WirePup build and verification targets.
# Builds are static (CGO disabled) as ADR-0002 and ADR-0012 require; the
# race target re-enables cgo because the race runtime needs it.

GO      ?= go
BIN     ?= bin/wirepup
PKG     := ./...
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

export CGO_ENABLED = 0

.DEFAULT_GOAL := help
.PHONY: help all build test race vet fmt-check check clean

help: ## List the available targets
	@grep -hE '^[a-zA-Z0-9_-]+:.*## ' $(MAKEFILE_LIST) | sort | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

all: build ## Build wirepup (alias of build)

build: ## Build the static wirepup binary into bin/
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/wirepup

test: ## Run the unit and golden tests
	$(GO) test $(PKG)

race: ## Run the tests under the race detector
	CGO_ENABLED=1 $(GO) test -race $(PKG)

vet: ## Run go vet
	$(GO) vet $(PKG)

fmt-check: ## Fail if any file needs gofmt
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then printf 'gofmt needed:\n%s\n' "$$out"; exit 1; fi

check: fmt-check vet test ## Run fmt-check, vet, and test (the pre-commit gate)

clean: ## Remove build output
	rm -rf bin
