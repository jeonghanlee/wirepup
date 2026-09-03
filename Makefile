# WirePup build and verification targets.
# Builds are static (CGO disabled) as ADR-0002 and ADR-0012 require; the
# race target re-enables cgo because the race runtime needs it.

GO      ?= go
BIN     ?= bin/wirepup
PKG     := ./...
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

export CGO_ENABLED = 0

.PHONY: all build test race vet fmt-check check clean

all: build

build:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/wirepup

test:
	$(GO) test $(PKG)

race:
	CGO_ENABLED=1 $(GO) test -race $(PKG)

vet:
	$(GO) vet $(PKG)

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then printf 'gofmt needed:\n%s\n' "$$out"; exit 1; fi

check: fmt-check vet test

clean:
	rm -rf bin
