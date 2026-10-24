<!-- ©AngelaMos | 2026 -->
<!-- DOCS.md -->

# Erinyes Usage Guide

This document covers every command, flag, environment variable, and output format in detail.
For the quick overview, see [README.md](README.md).

Signature authoring, scoring, and local configuration are documented below.

---

## Table of contents

1. [Install](#install)
2. [Global flags](#global-flags)
3. [Environment variables](#environment-variables)
4. [`scan`](#scan)
5. [`hunt`](#hunt)
6. [`sweep`](#sweep)
7. [`watch`](#watch)
8. [`verify`](#verify)
9. [`signatures`](#signatures)
10. [`version`](#version)
11. [Output formats](#output-formats)
12. [Exit codes](#exit-codes)
13. [GitHub token setup](#github-token-setup)
14. [Signature override](#signature-override)
15. [Signature authoring](#signature-authoring)
16. [Caching](#caching)
17. [Sweep tuning for large targets](#sweep-tuning-for-large-targets)
18. [Fork crawler](#fork-crawler)
19. [Just recipes reference](#just-recipes-reference)
20. [Troubleshooting](#troubleshooting)

---

## Install

**Release installer (Linux or macOS, amd64 or arm64):**

```bash
curl -fsSL https://angelamos.com/erinyes/install.sh | bash
```

The installer downloads the matching release archive from GitHub Releases, requires its SHA-256 to match `checksums.txt`, and installs to `~/.local/bin` by default. It adds the installation directory to your shell configuration if needed. If no release binary is available, it builds from source and obtains Go when necessary. A selected release tag is preserved during source fallback.

Options are `--prefix DIR`, `--version TAG`, `--from-source`, and `--help`. `ERINYES_INSTALL_DIR` supplies the default prefix. There is no option to skip checksum verification.

```bash
curl -fsSL https://angelamos.com/erinyes/install.sh | bash -s -- --version v0.1.0
```

**Go install (Go 1.25 or newer):**

```bash
go install github.com/CarterPerez-dev/erinyes/cmd/erinyes@latest
```

Use `@v0.1.0` for a fixed release or `@main` for the current development branch. `@latest` selects the highest release tag; without tags, Go can install a pseudo-version from the default branch. Tags alone are sufficient for Go module versioning. The shell installer's prebuilt path also needs the GitHub release archives. See the [Go module version rules](https://go.dev/ref/mod#version-queries).

**Private repository access:**

Unauthenticated downloads require a public repository. While Erinyes is private, authenticate the GitHub CLI with an account that can read it, then download and run the release installer:

```bash
gh auth login
gh release download v0.1.0 --repo CarterPerez-dev/erinyes --pattern install.sh --output /tmp/erinyes-install.sh
bash /tmp/erinyes-install.sh --version v0.1.0
```

The installer uses `gh` for authenticated release downloads when available. For private `go install`, configure Git credentials and bypass the public module proxy and checksum database for this module:

```bash
gh auth setup-git
GOPRIVATE=github.com/CarterPerez-dev/erinyes go install github.com/CarterPerez-dev/erinyes/cmd/erinyes@v0.1.0
```

**From source:**

```bash
git clone https://github.com/CarterPerez-dev/erinyes.git
cd erinyes
just build       # or: CGO_ENABLED=0 go build -trimpath -o erinyes ./cmd/erinyes
./erinyes version
```

**Uninstall:**

```bash
curl -fsSL https://github.com/CarterPerez-dev/erinyes/releases/latest/download/uninstall.sh | bash
```

For private releases, download `uninstall.sh` with `gh release download` in the same way. The uninstaller removes the binary and caches by default, preserves configuration, and supports `--prefix DIR`, `--keep-cache`, and `--purge`. `--purge` also removes configuration and user signatures.

---

## Global flags

These flags are inherited by subcommands. Report format and output-file selection apply to `scan`, `hunt`, and `sweep`; inspection commands and `watch` print text directly.

| Flag | Default | Purpose |
|---|---|---|
| `--signatures <path>` | builtin catalog | Load signatures from a file or directory instead of the compiled-in catalog |
| `--format {cli,json,markdown,sarif}` | `cli` | Output format for the report |
| `-o, --output <file>` | stdout | Write report to this file instead of stdout |
| `-v, --verbose` | off | Show clean and errored files, not just flagged ones |
| `--no-color` | auto | Disable ANSI colors (also auto-disabled when stdout is not a TTY) |

---

## Environment variables

| Var | Used by | Purpose |
|---|---|---|
| `GITHUB_TOKEN` | `hunt`, `sweep`, `watch` | First token source checked by the scanner. |
| `GH_TOKEN` | `hunt`, `sweep`, `watch`, installer via `gh` | Scanner fallback when `GITHUB_TOKEN` is empty; also recognized by the GitHub CLI. |
| `ERINYES_CORPUS` | `just corpus` | Path to a local directory of real malicious samples for regression testing. |
| `ERINYES_CONFIG_DIR` | catalog and configuration | Override the configuration directory. |
| `ERINYES_CACHE_DIR` | GitHub commands | Override the blob/search cache directory. |
| `XDG_CONFIG_HOME` | configuration | Base directory used when `ERINYES_CONFIG_DIR` is unset, except when Windows `APPDATA` is set. |
| `XDG_CACHE_HOME` | GitHub commands | Cache base; also controls the default watch-state location. |
| `NO_COLOR` | scanner and installer | Disable colored output when nonempty. |
| `TELEGRAM_BOT_TOKEN` | `watch` | Telegram token if `--telegram-token` is absent. |
| `TELEGRAM_CHAT_ID` | `watch` | Telegram chat ID if `--telegram-chat` is absent. |
| `ERINYES_INSTALL_DIR` | installer and uninstaller | Binary installation directory. |

If no token env var is set, erinyes also tries `gh auth token` from the GitHub CLI.

Configuration is read from `config.yaml` in the configuration directory. Defaults are `~/.config/erinyes` on Linux/macOS and `%APPDATA%/erinyes` on Windows. Supported settings used by commands are `format`, `no_color`, `cache_dir`, and `signatures_dir`. A command-line format overrides `format`; configured `no_color: true` remains enabled. Paths in the two directory settings expand `~/` and environment variables.

---

## `scan`

Walks a path and applies every signature whose `file_patterns` match. **Zero network calls.** Safe on an airgapped box with untrusted samples.

```bash
erinyes scan <path>
```

**Flags:**

| Flag | Default | Purpose |
|---|---|---|
| `--workers <n>` | one per CPU | Concurrent file workers |
| `--max-file-size <bytes>` | 16 MiB | Skip files larger than this |

**Behavior:**

- A directory is walked recursively; only files matching at least one signature's `file_patterns` are scanned.
- A single explicitly named file is scanned against **every** loaded signature regardless of pattern.
- Exit code 1 if anything is flagged; exit code 0 if the scan is clean. Lets you plug `erinyes scan` directly into CI.
- Suspicious results below the malicious threshold do not trigger exit 1. Check the report's error and skipped-file totals when assessing coverage.

**Examples:**

```bash
# Scan current working tree
erinyes scan .

# Scan a single file against every signature
erinyes scan ~/samples/suspicious.py

# JSON output into a file
erinyes scan . --format json -o report.json

# Verbose mode shows clean files too (handy for debugging patterns)
erinyes scan . -v
```

---

## `hunt`

Runs each `github_queries` entry declared by the selected signature(s) against GitHub code search, fetches every result, and scans it locally.

```bash
erinyes hunt <signature-id|all>
```

Pass `all` to run every signature's declared queries. Requires a GitHub token.

**Flags:**

| Flag | Default | Purpose |
|---|---|---|
| `-q, --query <q>` | sig's declared queries | Override the signature's queries with this one (repeatable) |
| `--limit <n>` | 0 (all) | Stop after this many results per query. GitHub caps at 1000. |
| `--rps <float>` | sig's declared rate | Override the signature's `retrohunt.rate_limit_rps` |
| `--include-forks` | false | Include forked repositories in results |
| `--search-ttl <dur>` | 1h | Reuse cached search responses younger than this (0 disables) |
| `--workers <n>` | 4 | Concurrent file fetches |
| `--cache-dir <path>` | XDG cache | Where to store the blob + search cache |
| `--no-cache` | off | Do not read or write the cache |
| `--dry-run` | off | Print the queries that would run and exit |

The client spaces code-search requests at least six seconds apart. `--rps` controls fetch pacing and can further slow search requests. Cached blobs avoid repeat downloads; repository queries still cost requests unless their search response is cached. An ad-hoc `--query` requires one signature, so it cannot be combined with `all` when several signatures are loaded.

**Examples:**

```bash
# Hunt all declared queries for the stage-1 PyMapper loader signature
erinyes hunt pymapper-fs-loader

# Search source code with one selected signature
erinyes hunt pymapper-fs-loader -q '"hmac.new" "bytearray" language:python'

# Dry-run to see what queries would hit the network
erinyes hunt all --dry-run
```

---

## `sweep`

Enumerates repositories, walks each one's git tree, and scans every file whose path matches a signature's `file_patterns`.

`sweep` reads repository trees, which can expose files absent from code search. A truncated tree response produces a warning; it does not establish complete repository coverage.

```bash
erinyes sweep <owner>              # every repo for that owner
erinyes sweep <owner>/<repo>       # one repo
erinyes sweep --query '<search>'   # every repo matching a GitHub repo search
```

**Flags:**

| Flag | Default | Purpose |
|---|---|---|
| `-q, --query <q>` | unset | Repo-search query instead of an owner target |
| `--limit <n>` | 0 (all) | Stop after this many repositories (GitHub repo search caps at 1000) |
| `--max-files <n>` | 0 (all) | Stop after this many candidate files per repository |
| `--max-file-size <bytes>` | 16 MiB | Skip blobs larger than this |
| `--bulk-after <n>` | 20 | Fetch a tarball when the candidate count reaches this value; 0 disables |
| `--no-bulk` | off | Always fetch file-by-file, never the tarball |
| `--include-forks` | false | Include forked repositories |
| `--include-archived` | false | Include archived repositories |
| `--cache-dir <path>` | XDG cache | Blob cache directory |
| `--no-cache` | off | Disable caching |
| `--rps <float>` | 10 | GitHub fetch requests per second; repository search has its own 30/minute cap |
| `--workers <n>` | 4 | Concurrent blob fetches within a repository |
| `--dry-run` | off | List the repositories that would be swept and exit |

**Examples:**

```bash
# Sweep every public repo an owner has
erinyes sweep hitechcloud-vietnam

# Metadata-pivot sweep
erinyes sweep --query 'created:2026-01-02 pushed:2026-09-20'

# Narrow sweep: one repo, cache off, dump JSON
erinyes sweep hkqr/my-free-code --no-cache --format json -o sweep.json

# Preview a huge sweep without touching blobs
erinyes sweep --query 'language:python stars:>100' --dry-run --limit 500
```

---

## `watch`

Poll repositories for changes in GitHub's `pushed_at` field. On a changed timestamp, compare `.py` and `.md` blob hashes against the saved state. The first pass establishes a baseline. Two or more push events in the same pass whose timestamps all fit within 15 minutes produce a `RELEASE-WAVE` event. This is a timing signal, not proof of coordination. The command does not scan changed file contents for malware or enumerate every intervening commit.

```bash
erinyes watch owner/repo --once --no-notify
erinyes watch --targets-file targets.txt --interval 15 --no-notify
```

Targets are positional `owner/repo` arguments or one repository per line in a file. Blank lines and lines beginning with `#` are ignored; duplicate targets are removed. Create your own target list.

| Flag | Default | Purpose |
|---|---|---|
| `-f, --targets-file <file>` | unset | Append repositories from a text file |
| `--state <file>` | `~/.cache/erinyes/watch-state.json` | Persistent state, with `XDG_CACHE_HOME` respected |
| `--interval <minutes>` | 15 | Poll interval, clamped to at least 5 minutes |
| `--once` | false | Run one pass and exit |
| `--no-notify` | false | Print events without sending webhook or Telegram messages |
| `--webhook <url>` | unset | POST a JSON object with a `text` field for each event |
| `--telegram-token <token>` | environment | Telegram bot token |
| `--telegram-chat <id>` | environment | Telegram chat ID |
| `--rps <float>` | 2 | GitHub requests per second |
| `--cache-dir <path>` | configured cache | Blob cache directory; does not relocate watch state |

Events are plain text on stdout. Per-repository failures produce `ERROR` events; notification failures are logged to stderr. State records observations even if notification delivery fails, so notifications are not guaranteed to arrive exactly once. `--once` does not return a malware verdict; inspect its event output for individual repository failures.

## `verify`

Checks a SHA-256 hash, or hashes a local file, against the loaded catalog of known-malicious hashes. Signature overrides and user overlays apply.

```bash
erinyes verify <sha256-hex>
erinyes verify <path/to/file>
```

Prints the signature/sample metadata and exits 1 for a known hash. A catalog miss exits 0 and is not proof that a file is clean. No network calls.

---

## `signatures`

Inspects the loaded signature catalog without scanning anything.

```bash
erinyes signatures list                # list the loaded catalog
erinyes signatures show <sig-id>       # dump a single signature
erinyes signatures validate <dir>      # lint and validate YAML files
```

`validate` accepts a YAML file or the immediate `.yaml`/`.yml` files in a directory. It checks schema fields, indicator names, regular expressions, weights, thresholds, hashes, and duplicate signature IDs. Warnings do not fail validation; errors exit 2. `sig` and `sigs` are aliases for `signatures`. There is no separate `signatures lint` subcommand.

---

## `version`

```bash
erinyes version
```

Prints the tool version, available commit/build metadata, catalog schema version, Go runtime, and loaded signatures. Release builds inject the tag. `go install ...@version` reads its version from Go's embedded module metadata. An unversioned source build reports `dev`; unavailable commit/date fields are omitted.

---

## Output formats

Set with `--format`.

| Format | What it is | Primary use |
|---|---|---|
| `cli` | Colored human-readable table with per-indicator breakdown | Terminal use |
| `json` | Structured JSON with per-file findings, scores, and summary totals | Programmatic / pipelines |
| `markdown` | GitHub-flavored Markdown report with a findings table | Issue / PR body, write-ups |
| `sarif` | SARIF v2.1.0 | GitHub Advanced Security code-scanning upload |

**SARIF upload hint:**

```bash
erinyes scan . --format sarif -o report.sarif
gzip -c report.sarif | base64 | tr -d '\n' > report.sarif.gz.b64
gh api -X POST /repos/OWNER/REPO/code-scanning/sarifs \
  -f commit_sha="$(git rev-parse HEAD)" \
  -f ref="refs/heads/main" \
  -F sarif=@report.sarif.gz.b64
```

GitHub requires the SARIF JSON to be gzip-compressed and Base64-encoded. The `just sarif <path>` recipe builds the CLI and writes a report, accepting the scanner's exit 1 when files are flagged. It does not upload anything. See the [GitHub upload contract](https://docs.github.com/en/rest/code-scanning/code-scanning#upload-an-analysis-as-sarif-data).

---

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Command completed; scans have no malicious verdict and `verify` found no catalog match |
| 1 | At least one malicious scan verdict, or a known hash matched by `verify` |
| 2 | Usage, configuration, signature, filesystem, or general API error |
| 3 | `hunt`/`sweep` exhausted GitHub rate-limit retries |

Individual file or repository errors can appear in a report without failing the entire scan. Inspect `errors`, `skipped`, and stderr before treating exit 0 as complete coverage.

---

## GitHub token setup

`hunt`, `sweep`, and `watch` require a token. `hunt --dry-run` is offline; `sweep --dry-run` still queries GitHub for repository metadata.

1. Set `GITHUB_TOKEN` or `GH_TOKEN` in your environment.
2. Authenticate the GitHub CLI with `gh auth login`; Erinyes can read that token automatically.

**Required scopes:**

- Public metadata and content endpoints do not require repository write access. Use the minimum permissions needed for the selected endpoints.
- Private repositories require token access to those repositories; tree/blob reads use the fine-grained `Contents: read` permission.
- A classic `public_repo` scope includes write capabilities and is not a read-only scope. Consult the [GitHub endpoint permissions](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens) and [code-search authentication rules](https://docs.github.com/en/rest/search/search#search-code) for your token type.

**Rate limits:**

- Code search: 10 requests/minute
- Core API (sweep tree walks): 5000 req/hour authenticated
- Repository search (sweep `--query`): 30 req/min

These are standard authenticated limits; GitHub may apply different primary buckets or secondary limits. Token permission breadth does not by itself imply a larger bucket. The client caches responses and backs off when limits are reached.

---

## Signature override

By default erinyes loads the compiled-in catalog. To work on signatures without rebuilding:

```bash
# Point at a single file
erinyes scan . --signatures ./signatures/pymapper_fs.yaml

# Point at a directory
erinyes scan . --signatures ./signatures/
```

Combined with `just validate`, this is the loop for signature authoring:

```bash
# Edit a signature, then:
just validate                             # lint + schema check
erinyes scan testdata/known_malicious \
  --signatures ./signatures               # true-positive check
erinyes scan testdata/known_benign \
  --signatures ./signatures               # false-positive check
```

---

## Signature authoring

The default catalog embeds `signatures/*.yaml` at build time. Without `--signatures`, YAML files from the configured user signatures directory extend it or replace entries with the same ID. `--signatures` replaces both the builtin catalog and user overlays.

```yaml
id: example-rule
version: 1
family: Example
severity: high
confidence_threshold: 60
file_patterns: ["*.py"]
description: Example schema; replace the literal with a validated indicator.
indicators:
  - name: marker
    weight: 60
    type: literal
    pattern: example-marker
retrohunt:
  github_queries: ['"example-marker" language:python']
  rate_limit_rps: 0.17
```

IDs use lowercase letters, digits, and internal hyphens. Schema `version` is 1. Supply a family, severity (`critical`, `high`, `medium`, or `low`), file patterns, and at least one indicator. Indicators have unique `name` values, weights from 0 to 100, and a `literal` or Go/RE2 `regex` pattern. The default indicator type is `regex`; `ast` is reserved and rejected. Use `(?m)` when regex anchors must match each line.

`confidence_threshold` must be between 0 and 100 and no larger than the sum of weights. Each matching indicator contributes its weight once, regardless of occurrence count. Scores are not capped at 100 and are not probabilities. Scores at or above the threshold are `malicious`; scores at or above half the threshold, rounded down, are `suspicious`. Lower scores are `clean`. A known hash forces a malicious verdict without changing the indicator score.

Optional fields are `first_seen`, `contributor`, `description`, `references`, `retrohunt`, and `known_hashes`. Hash entries contain `sha256`, `label`, and optional `first_seen`. Validate every change and check representative positive and benign inputs. The Python subprocess activation rule is a hunting heuristic: legitimate programs can launch adjacent scripts too.

## Caching

The cache stores:

- GitHub blobs by Git object SHA, used by `hunt` and per-blob sweeps
- Code-search responses by query, used by `hunt --search-ttl` (default 1h)

Default cache paths are `$XDG_CACHE_HOME/erinyes` or `~/.cache/erinyes` on Linux/macOS, and `%LOCALAPPDATA%/erinyes/cache` on Windows. `ERINYES_CACHE_DIR`, the `cache_dir` setting, and `--cache-dir` can override this, with the flag taking precedence. `hunt` and `sweep` accept `--no-cache`. Sweeps still fetch repository metadata/trees; tarball sweeps download the archive again. Repository-search responses are not cached.

Blob and search caches rebuild after removal. Watch state is separate application state: removing it resets the baseline. `--state` sets its location explicitly; `ERINYES_CACHE_DIR` and `--cache-dir` do not move it.

---

## Sweep tuning for large targets

A sweep across an owner with many repos needs some care.

| Situation | Flag |
|---|---|
| You just want a list of what *would* be swept | `--dry-run` |
| First pass, keep API load low | `--limit 25` |
| You know only one signature's file patterns matter | Use `--signatures <narrow dir>` |
| A single repo has thousands of candidate files | Leave `--bulk-after 20` enabled for tarball download |
| You hit a rate-limit wall | Lower `--rps` and `--workers`; retain the blob cache |
| Repo is huge and you only care about one path | Clone and `scan` that path; sweep is tree-wide |

Sweep defaults to 10 fetch requests/second independently of signature hunt rates. Lower `--rps` to reduce load. GitHub's own primary and secondary limits still apply.

## Fork crawler

`scripts/fork-crawl.sh` enumerates forks of its fixed carrier list, queues unique fork-owner names, and runs `erinyes sweep` for each owner. It requires Bash, `curl`, `jq`, an `erinyes` binary on `PATH`, and `GITHUB_TOKEN`.

```bash
bash scripts/fork-crawl.sh enum
bash scripts/fork-crawl.sh sweep
bash scripts/fork-crawl.sh all
```

`all` is the default. Output goes to `~/erinyes-sweeps`; override `OUT_DIR`, `QUEUE_FILE`, `DONE_FILE`, or `LOG_FILE` as needed. `SWEEP_SLEEP_SECONDS` defaults to 45 and `FORK_API_SLEEP_SECONDS` to 2. Completed owners, including sweeps with malicious findings, are recorded in the done file; failures remain queued. Sweeps exclude fork repositories by default, so this helper examines the fork owners' non-fork repositories rather than scanning every fork itself. The embedded carrier list is a historical seed set, not a live census.

---

## Just recipes reference

Every command and dev task has a `just` recipe. From the repo root:

```bash
just                       # list every recipe
just build                 # build local binary
just install               # go install to $GOBIN
just build-all             # linux/darwin amd64+arm64, windows amd64
just package               # cross-compile + tar/zip + checksums.txt
just test                  # test with race
just test-fast             # test without race
just cover                 # coverage report
just bench                 # scan-package benchmarks
just lint                  # golangci-lint
just fmt                   # gofmt + go mod tidy
just vet                   # go vet
just check                 # fmt + vet + lint + test
just validate              # signature catalog lint + schema check
just corpus <dir>          # regression against a local corpus (ERINYES_CORPUS)
just scan <path>           # erinyes scan <path>
just hunt <sig>            # erinyes hunt <sig>
just sweep <target>        # erinyes sweep <target>
just sweep-query '<q>'     # erinyes sweep --query '<q>'
just sarif <path> [out]    # scan into SARIF with upload hint
just clean                 # remove build artifacts
just installer-check       # bash syntax and installer help checks
```

---

## Troubleshooting

**`401 Bad credentials` on hunt/sweep.**
Check the token's validity and access to the target repository. `gh auth status` verifies the CLI authentication without printing the token.

**`403 API rate limit exceeded`.**
You hit the 10 req/min code-search cap or the 5000/hr core cap. Wait, or set `--rps` lower. Caching helps a lot on reruns.

**`signatures validate` fails on a brand-new YAML.**
Use the [signature schema above](#signature-authoring). The threshold field is `confidence_threshold`, and each indicator has a unique `name`. Unknown fields and unsupported regex syntax fail validation.

**Scan says "signatures: 0 loaded".**
Either the builtin catalog failed to compile in (rebuild) or `--signatures <path>` pointed at an empty / malformed directory.

**`erinyes: command not found` after `go install`.**
`$GOBIN` (or `$(go env GOPATH)/bin`) is not on your `PATH`. Add it to your shell profile.

**Sweep stops at exactly 1000 repos.**
GitHub caps a repository-search result set at 1,000. Narrow the query with `language:`, `stars:`, or date ranges to split the result set.

---

## Status and roadmap

Erinyes has four builtin signatures and three synthetic PyMapper loader fixtures. Existing tests also cover benign fixtures, signature validation, command output, and GitHub API behavior with local stubs. These checks do not measure a production false-positive rate or exhaustive malware coverage.

For signature contributions, include a source-grounded description, synthetic positive and negative test cases, and the validation results. Keep executable malware samples out of the repository.
