# ©AngelaMos | 2026
# Makefile
#
# A justfile is the primary interface. This exists so contributors without
# `just` installed get the same targets.

BINARY    := erinyes
PKG       := ./cmd/erinyes
DIST      := dist
VERSION   := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT    := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE      := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS   := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

.PHONY: all build install build-all package test test-race bench cover lint vet fmt check validate clean help

all: build

help:
	@grep -E '^[a-z-]+:.*?##' $(MAKEFILE_LIST) | sed 's/:.*##/\t/' | expand -t24

build: ## build a binary for this platform
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)

install: ## go install into GOBIN
	CGO_ENABLED=0 go install -trimpath -ldflags "$(LDFLAGS)" $(PKG)

build-all: ## cross-compile every supported platform
	rm -rf $(DIST)
	@for platform in $(PLATFORMS); do \
		os=$${platform%%/*}; arch=$${platform##*/}; \
		stage="$(DIST)/$(BINARY)_$${os}_$${arch}"; \
		out="$$stage/$(BINARY)"; \
		if [ "$$os" = "windows" ]; then out="$$out.exe"; fi; \
		mkdir -p "$$stage"; \
		echo "  building $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
			go build -trimpath -ldflags "$(LDFLAGS)" -o "$$out" $(PKG) || exit 1; \
	done

package: build-all ## tarballs, zip and checksums.txt
	@ver=$$(echo "$(VERSION)" | sed 's/^v//'); \
	cd $(DIST) && for stage in */; do \
		stage=$${stage%/}; suffix=$${stage#$(BINARY)_}; \
		cp ../LICENSE ../README.md "$$stage/"; \
		if [ -f "$$stage/$(BINARY).exe" ]; then \
			(cd "$$stage" && zip -qr "../$(BINARY)_$${ver}_$${suffix}.zip" .); \
		else \
			tar -czf "$(BINARY)_$${ver}_$${suffix}.tar.gz" -C "$$stage" .; \
		fi; \
		rm -rf "$$stage"; \
	done; \
	(sha256sum $(BINARY)_* 2>/dev/null || shasum -a 256 $(BINARY)_*) > checksums.txt
	@ls -1 $(DIST)

test: ## unit and integration tests
	go test ./...

test-race: ## tests under the race detector
	go test ./... -race

bench: ## scan throughput benchmarks
	go test ./internal/scan/ -run XXX -bench . -benchmem

cover: ## coverage summary
	go test ./... -coverprofile=coverage.out
	go tool cover -func=coverage.out | tail -1

lint: ## golangci-lint
	golangci-lint run ./...

vet: ## go vet
	go vet ./...

fmt: ## gofmt and tidy
	gofmt -w .
	go mod tidy

validate: ## lint the shipped signature catalog
	go run $(PKG) signatures validate ./signatures

check: fmt vet lint test-race validate ## everything CI runs

clean: ## remove build output
	rm -rf $(DIST) $(BINARY) coverage.out erinyes.sarif
