# ©AngelaMos | 2026
# justfile

set shell := ["bash", "-euo", "pipefail", "-c"]

binary    := "erinyes"
pkg       := "./cmd/erinyes"
dist      := "dist"
version   := `git describe --tags --always --dirty 2>/dev/null || echo dev`
commit    := `git rev-parse --short HEAD 2>/dev/null || echo unknown`
date      := `date -u +%Y-%m-%dT%H:%M:%SZ`
ldflags   := "-s -w -X main.version=" + version + " -X main.commit=" + commit + " -X main.date=" + date

platforms := "linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64"

default:
    @just --list

build:
    CGO_ENABLED=0 go build -trimpath -ldflags "{{ldflags}}" -o {{binary}} {{pkg}}
    @echo "built ./{{binary}} {{version}}"

install:
    CGO_ENABLED=0 go install -trimpath -ldflags "{{ldflags}}" {{pkg}}
    @echo "installed {{binary}} to $(go env GOBIN 2>/dev/null || echo "$(go env GOPATH)/bin")"

build-all:
    rm -rf {{dist}}
    for platform in {{platforms}}; do \
        os="${platform%%/*}"; arch="${platform##*/}"; \
        stage="{{dist}}/{{binary}}_${os}_${arch}"; \
        out="${stage}/{{binary}}"; \
        if [ "$os" = "windows" ]; then out="${out}.exe"; fi; \
        mkdir -p "$stage"; \
        echo "  building ${os}/${arch}"; \
        CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
            go build -trimpath -ldflags "{{ldflags}}" -o "$out" {{pkg}}; \
    done
    @echo "binaries in {{dist}}/"

package: build-all
    #!/usr/bin/env bash
    set -euo pipefail
    ver="$(echo '{{version}}' | sed 's/^v//')"
    cd {{dist}}
    for stage in */; do
        stage="${stage%/}"
        suffix="${stage#{{binary}}_}"
        cp ../LICENSE ../README.md "$stage/"
        if [ -f "$stage/{{binary}}.exe" ]; then
            (cd "$stage" && zip -qr "../{{binary}}_${ver}_${suffix}.zip" .)
        else
            tar -czf "{{binary}}_${ver}_${suffix}.tar.gz" -C "$stage" .
        fi
        rm -rf "$stage"
    done
    if command -v sha256sum >/dev/null; then
        sha256sum {{binary}}_* > checksums.txt
    else
        shasum -a 256 {{binary}}_* > checksums.txt
    fi
    ls -1

test:
    go test ./... -race

test-fast:
    go test ./...

cover:
    go test ./... -coverprofile=coverage.out
    go tool cover -func=coverage.out | tail -1
    @echo "html report: go tool cover -html=coverage.out"

bench:
    go test ./internal/scan/ -run XXX -bench . -benchmem

lint:
    golangci-lint run ./...

fmt:
    gofmt -w .
    go mod tidy

vet:
    go vet ./...

check: fmt vet lint test
    @echo "all checks passed"

validate:
    go run {{pkg}} signatures validate ./signatures

# Regression against Carter's local corpus of real stage-1 samples.
corpus dir:
    ERINYES_CORPUS="{{dir}}" go test ./internal/scan/ -run TestRealCorpusRegression -v

scan path:
    go run {{pkg}} scan {{path}}

hunt sig="pymapper-fs-loader":
    go run {{pkg}} hunt {{sig}}

sarif path out="erinyes.sarif":
    go run {{pkg}} scan {{path}} --format sarif --output {{out}}
    @echo "upload with: gh api -X POST /repos/OWNER/REPO/code-scanning/sarifs -f commit_sha=... -f ref=... -f sarif=@{{out}}"

clean:
    rm -rf {{dist}} {{binary}} coverage.out erinyes.sarif

installer-check:
    bash -n install.sh
    bash -n uninstall.sh
    ./install.sh --help >/dev/null
    @echo "installer scripts are syntactically clean"
