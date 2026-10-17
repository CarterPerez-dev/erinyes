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

[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go&logoColor=white)](https://go.dev)
[![License: AGPLv3](https://img.shields.io/badge/License-AGPL_v3-purple.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Docs](https://img.shields.io/badge/Docs-DOCS.md-2A6DB2?style=flat)](DOCS.md)
[![GitHub Code Search](https://img.shields.io/badge/GitHub-code%20search-181717?style=flat&logo=github&logoColor=white)](https://docs.github.com/en/rest/search/search#search-code)

> YAML-signature-driven hunter for obfuscated malware hiding in open source. Scan a checkout, retrohunt code search, sweep every file in a target's repos.

*This is the quick overview. Full usage, flags, output formats, signature authoring and sweep tuning are in [DOCS.md](DOCS.md).*

## What It Does

- YAML signature catalog with per-indicator scoring and declared thresholds
- Three hunt modes: `scan` (local, zero network), `hunt` (GitHub code search), `sweep` (whole-repo tree walk via GitHub Trees API)
- GitHub metadata-pivot sweeps (`--query 'created:X pushed:Y'`) that catch samples code search never indexes
- Output as colored CLI, JSON, Markdown, or SARIF v2.1.0
- Known-malicious hash catalog for instant verdicts on already-seen samples
- Signature linter + validator built in (`signatures validate`, `signatures lint`)
- No telemetry. No phone home. Scan mode makes zero network calls, ever.

## Install

```bash
curl -fsSL https://angelamos.com/erinyes/install.sh | bash
```

Or with Go:

```bash
go install github.com/CarterPerez-dev/erinyes/cmd/erinyes@latest
```

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
| `erinyes verify <hash\|file>` | Check a hash or a file against the known-malicious catalog | — |
| `erinyes signatures list` | List the loaded signature catalog | `just validate` (lint + validate) |
| `erinyes signatures validate <dir>` | Lint and validate signature YAML files | — |
| `erinyes version` | Print tool version, catalog version, Go runtime | — |

**Common flags:** `--format {cli,json,markdown,sarif}`, `--output <file>`, `--signatures <dir>`, `--verbose`, `--no-color`

Full flag reference, env-var contract, GitHub token scopes, and sweep-rate tuning are in [DOCS.md](DOCS.md).

## Build & Dev

| Task | Just recipe | Raw command |
|---|---|---|
| Build local binary | `just build` | `CGO_ENABLED=0 go build -trimpath -o erinyes ./cmd/erinyes` |
| Install to `$GOBIN` | `just install` | `go install -trimpath ./cmd/erinyes` |
| Cross-compile all platforms | `just build-all` | — |
| Package release archives + checksums | `just package` | — |
| Run full test suite with race | `just test` | `go test ./... -race` |
| Fast test (no race) | `just test-fast` | `go test ./...` |
| Coverage report | `just cover` | — |
| Benchmarks | `just bench` | — |
| Format + tidy | `just fmt` | `gofmt -w . && go mod tidy` |
| Lint (golangci-lint) | `just lint` | — |
| Vet | `just vet` | `go vet ./...` |
| All checks (fmt + vet + lint + test) | `just check` | — |
| Signature catalog validation | `just validate` | `go run ./cmd/erinyes signatures validate ./signatures` |
| Regression against a local corpus | `just corpus <dir>` | — |
| SARIF scan + upload hint | `just sarif <path>` | — |
| Clean build artifacts | `just clean` | — |
| Installer syntax check | `just installer-check` | — |

## Status

Erinyes is actively developed. The signature catalog is intentionally small and tight — every rule in `signatures/` is derived from a confirmed sample, not from pattern-guessing. More signatures land as new families are reverse-engineered.

Signature authoring guide: [`docs/signature-format.md`](docs/signature-format.md).
Architecture overview: [`docs/architecture.md`](docs/architecture.md).

## License

AGPL 3.0 — see [LICENSE](LICENSE).
