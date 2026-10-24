<!-- ©AngelaMos | 2026 -->
<!-- README.md -->

```ruby
      ___           ___                       ___           ___           ___           ___     
     /\  \         /\  \          ___        /\__\         |\__\         /\  \         /\  \    
    /::\  \       /::\  \        /\  \      /::|  |        |:|  |       /::\  \       /::\  \   
   /:/\:\  \     /:/\:\  \       \:\  \    /:|:|  |        |:|  |      /:/\:\  \     /:/\ \  \  
  /::\~\:\  \   /::\~\:\  \      /::\__\  /:/|:|  |__      |:|__|__   /::\~\:\  \   _\:\~\ \  \ 
 /:/\:\ \:\__\ /:/\:\ \:\__\  __/:/\/__/ /:/ |:| /\__\     /::::\__\ /:/\:\ \:\__\ /\ \:\ \ \__\
 \:\~\:\ \/__/ \/_|::\/:/  / /\/:/  /    \/__|:|/:/  /    /:/~~/~    \:\~\:\ \/__/ \:\ \:\ \/__/
  \:\ \:\__\      |:|::/  /  \::/__/         |:/:/  /    /:/  /       \:\ \:\__\    \:\ \:\__\  
   \:\ \/__/      |:|\/__/    \:\__\         |::/  /     \/__/         \:\ \/__/     \:\/:/  /  
    \:\__\        |:|  |       \/__/         /:/  /                     \:\__\        \::/  /   
     \/__/         \|__|                     \/__/                       \/__/         \/__/    
```

[![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go&logoColor=white)](https://go.dev)
[![License: AGPLv3](https://img.shields.io/badge/License-AGPL_v3-purple.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Docs](https://img.shields.io/badge/Docs-DOCS.md-2A6DB2?style=flat)](DOCS.md)
[![GitHub Code Search](https://img.shields.io/badge/GitHub-code%20search-181717?style=flat&logo=github&logoColor=white)](https://docs.github.com/en/rest/search/search#search-code)

> YAML-signature-driven hunter for obfuscated malware hiding in open source. Scan a checkout, retrohunt code search, sweep every file in a target's repos.

*This is the quick overview. Full usage, flags, output formats, signature authoring and sweep tuning are in [DOCS.md](DOCS.md).*

## What It Does

- YAML signature catalog with per-indicator scoring and declared thresholds
- Three hunt modes: `scan` (local, zero network), `hunt` (GitHub code search), `sweep` (whole-repo tree walk via GitHub Trees API)
- Repository monitoring with `watch`, persistent state, and optional webhook or Telegram notifications
- GitHub metadata-pivot sweeps (`--query 'created:X pushed:Y'`) that catch samples code search never indexes
- Output as colored CLI, JSON, Markdown, or SARIF v2.1.0
- Known-malicious hashes force a malicious verdict while preserving the indicator score
- Signature inspection and validation built in (`signatures list`, `show`, `validate`)
- No telemetry. No phone home. Scan mode makes zero network calls, ever.

## Install

```bash
curl -fsSL https://angelamos.com/erinyes/install.sh | bash
```

Or with Go 1.25 or newer:

```bash
go install github.com/CarterPerez-dev/erinyes/cmd/erinyes@latest
```

Use `@v0.1.0` to pin the first tagged release. The shell installer supports Linux and macOS on amd64/arm64; release archives also include Windows amd64. Private repository access and version selection are covered in [DOCS.md](DOCS.md#install).

## Quick Start

```bash
erinyes scan .
```

> [!TIP]
> This project uses [`just`](https://github.com/casey/just) as a command runner. Type `just` from the repo root to see every available recipe.
>
> Install: `curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`

## Commands

| Command | What it does | Just recipe |
|---|---|---|
| `erinyes scan <path>` | Scan a file or directory against the signature catalog (offline) | `just scan <path>` |
| `erinyes hunt <signature>` | Retrohunt GitHub code search for new instances of a signature | `just hunt <sig>` |
| `erinyes sweep <owner>` | Walk every file in every repo for a GitHub owner | `just sweep <owner>` |
| `erinyes sweep --query '<q>'` | Metadata-pivot sweep on a GitHub repo search query | `just sweep-query '<q>'` |
| `erinyes watch <owner/repo> --once --no-notify` | Poll repository timestamps and tracked file hashes | Run directly |
| `erinyes verify <hash\|file>` | Check a hash or a file against the known-malicious catalog | Run directly |
| `erinyes signatures list` | List the loaded signature catalog | Run directly |
| `erinyes signatures validate <path>` | Lint and validate signature YAML files | `just validate` |
| `erinyes version` | Print tool version, catalog schema, Go runtime | Run directly |

**Common flags:** `--format {cli,json,markdown,sarif}`, `--output <file>`, `--signatures <dir>`, `--verbose`, `--no-color`

Full flag reference, env-var contract, GitHub token scopes, and sweep-rate tuning are in [DOCS.md](DOCS.md).

## Build & Dev

| Task | Just recipe | Raw command |
|---|---|---|
| Build local binary | `just build` | `CGO_ENABLED=0 go build -trimpath -o erinyes ./cmd/erinyes` |
| Install to `$GOBIN` | `just install` | `go install -trimpath ./cmd/erinyes` |
| Cross-compile five supported targets | `just build-all` | See justfile |
| Package release archives + checksums | `just package` | See justfile |
| Run full test suite with race | `just test` | `go test ./... -race` |
| Fast test (no race) | `just test-fast` | `go test ./...` |
| Coverage report | `just cover` | See justfile |
| Benchmarks | `just bench` | See justfile |
| Format + tidy | `just fmt` | `gofmt -w . && go mod tidy` |
| Lint (golangci-lint v2) | `just lint` | `golangci-lint run ./...` |
| Vet | `just vet` | `go vet ./...` |
| Format, tidy, vet, lint and test | `just check` | See justfile |
| Signature catalog validation | `just validate` | `go run ./cmd/erinyes signatures validate ./signatures` |
| Regression against a local corpus | `just corpus <dir>` | See justfile |
| SARIF report | `just sarif <path>` | See justfile |
| Clean build artifacts | `just clean` | See justfile |
| Installer syntax and help checks | `just installer-check` | See justfile |

## Status

The catalog contains four signatures: two PyMapper loader signatures, a Python activation-helper heuristic, and a cross-platform dropper signature. Structural matches identify files for investigation; the activation-helper rule can also match legitimate subprocess code. Known hashes identify exact cataloged files. A clean result means no selected signature reached its threshold.

Signature authoring and scoring: [DOCS.md](DOCS.md#signature-authoring).

## License

AGPL 3.0. See [LICENSE](LICENSE).
