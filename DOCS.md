<!-- ©AngelaMos | 2026 -->
<!-- DOCS.md -->

# Erinyes — Full Usage Guide

This document covers every command, flag, environment variable, and output format in detail.
For the quick overview, see [README.md](README.md).

For signature authoring, see [`docs/signature-format.md`](docs/signature-format.md).
For internal architecture, see [`docs/architecture.md`](docs/architecture.md).

---

## Table of contents

1. [Install](#install)
2. [Global flags](#global-flags)
3. [Environment variables](#environment-variables)
4. [`scan` — local, offline](#scan--local-offline)
5. [`hunt` — GitHub code search](#hunt--github-code-search)
6. [`sweep` — whole-repo tree walk](#sweep--whole-repo-tree-walk)
7. [`verify` — hash catalog lookup](#verify--hash-catalog-lookup)
8. [`signatures` — inspect / lint / validate](#signatures--inspect--lint--validate)
9. [`version`](#version)
10. [Output formats](#output-formats)
11. [Exit codes](#exit-codes)
12. [GitHub token setup](#github-token-setup)
13. [Signature override](#signature-override)
14. [Caching](#caching)
15. [Sweep tuning for large targets](#sweep-tuning-for-large-targets)
16. [Just recipes reference](#just-recipes-reference)
17. [Troubleshooting](#troubleshooting)

---

## Install

**Hosted installer (one line):**

```bash
curl -fsSL https://angelamos.com/erinyes/install.sh | bash
```

The installer detects your OS/arch, downloads the matching release archive, verifies its SHA-256 against `checksums.txt`, and places the binary on `PATH`. Pass `--help` to the piped install to see its own flags (install prefix, version pin, no-verify).

**Go install (if you have Go 1.24+):**

```bash
go install github.com/CarterPerez-dev/erinyes/cmd/erinyes@latest
```

**From source:**

```bash
git clone git@github.com:CarterPerez-dev/erinyes.git
cd erinyes
just build       # or: CGO_ENABLED=0 go build -trimpath -o erinyes ./cmd/erinyes
./erinyes version
```

**Uninstall:**

```bash
curl -fsSL https://angelamos.com/erinyes/uninstall.sh | bash
```

---

## Global flags

These flags work on every command.

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
| `GITHUB_TOKEN` | `hunt`, `sweep` | GitHub API token. Needs `public_repo` read scope (classic) or `repository: read` (fine-grained). |
| `GH_TOKEN` | `hunt`, `sweep` | Alternate name — picked up if `GITHUB_TOKEN` is unset. |
| `ERINYES_CORPUS` | `just corpus` | Path to a local directory of real malicious samples for regression testing. |
| `ERINYES_CONFIG_DIR` | internal | Override XDG config dir (mostly for tests). |

If no token env var is set, erinyes also tries `gh auth token` from the GitHub CLI.

---

## `scan` — local, offline

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
- A single explicitly named file is scanned against **every** loaded signature regardless of pattern — useful for probing an unknown sample.
- Exit code 1 if anything is flagged; exit code 0 if the scan is clean. Lets you plug `erinyes scan` directly into CI.

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

## `hunt` — GitHub code search

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

**Rate reality:** GitHub's code-search endpoint is capped at 10 requests per minute. A wide hunt is **paced**, not fast — expect several minutes for a signature with many queries. The blob cache is keyed by git sha, so re-running costs almost nothing.

**Examples:**

```bash
# Hunt all declared queries for the stage-1 PyMapper loader signature
erinyes hunt pymapper-fs-loader

# Metadata-pivot query — the pattern that catches low-star repos
erinyes hunt pymapper-fs-loader -q 'created:2026-01-02 pushed:2026-09-20'

# Dry-run to see what queries would hit the network
erinyes hunt all --dry-run
```

---

## `sweep` — whole-repo tree walk

Enumerates repositories, walks each one's git tree, and scans every file whose path matches a signature's `file_patterns`.

Where `hunt` asks GitHub's code *index* what it already knows, `sweep` reads the repositories themselves. That reaches files the index never covered — the way a low-star repo with a fresh payload stays invisible to `hunt`.

```bash
erinyes sweep <owner>              # every repo for that owner
erinyes sweep <owner>/<repo>       # one repo
erinyes sweep --query '<search>'   # every repo matching a GitHub repo search
```

**Flags:**

| Flag | Default | Purpose |
|---|---|---|
| `--query <q>` | — | Repo-search query instead of an owner target |
| `--limit <n>` | 0 (all) | Stop after this many repositories (GitHub repo search caps at 1000) |
| `--max-files <n>` | 0 (all) | Stop after this many candidate files per repository |
| `--max-file-size <bytes>` | 16 MiB | Skip blobs larger than this |
| `--bulk-after <n>` | 20 | If a repo has more than this many candidate files, fetch the whole tarball in one request |
| `--no-bulk` | off | Always fetch file-by-file, never the tarball |
| `--include-forks` | false | Include forked repositories |
| `--include-archived` | false | Include archived repositories |
| `--cache-dir <path>` | XDG cache | Blob cache directory |
| `--no-cache` | off | Disable caching |
| `--dry-run` | off | List the repositories that would be swept and exit |

**Examples:**

```bash
# Sweep every public repo an owner has
erinyes sweep hitechcloud-vietnam

# Metadata-pivot sweep — the pattern that caught the four Jan-02 batch repos
erinyes sweep --query 'created:2026-01-02 pushed:2026-09-20'

# Narrow sweep: one repo, cache off, dump JSON
erinyes sweep hkqr/my-free-code --no-cache --format json -o sweep.json

# Preview a huge sweep without touching blobs
erinyes sweep --query 'language:python stars:>100' --dry-run --limit 500
```

---

## `verify` — hash catalog lookup

Checks a SHA-256 hash — or hashes a local file and checks that — against erinyes's built-in catalog of known-malicious hashes.

```bash
erinyes verify <sha256-hex>
erinyes verify <path/to/file>
```

Returns a verdict and the signature/sample metadata if there is a match. No network calls.

---

## `signatures` — inspect / lint / validate

Inspects the loaded signature catalog without scanning anything.

```bash
erinyes signatures list                # list the loaded catalog
erinyes signatures show <sig-id>       # dump a single signature
erinyes signatures validate <dir>      # lint and validate YAML files
```

`validate` is what the `just validate` recipe runs. It parses every YAML file in the given directory, checks the schema, verifies indicator references, and reports any errors.

---

## `version`

```bash
erinyes version
```

Prints the tool version (git-describe tag + commit + build date), the catalog version, and the Go runtime version. Build metadata is injected at compile time via `-ldflags` — if you built from source without the ldflags block, these read as `dev` / `unknown`.

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
gh api -X POST /repos/OWNER/REPO/code-scanning/sarifs \
  -f commit_sha="$(git rev-parse HEAD)" \
  -f ref="refs/heads/main" \
  -f sarif=@report.sarif
```

The `just sarif <path>` recipe generates the file and prints the exact upload command.

---

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Clean scan — nothing flagged |
| 1 | **At least one file flagged** — this is what you plug into CI |
| 2 | Usage error (bad flag, missing arg) |
| 3 | Signature catalog failed to load |
| 4 | GitHub API error (hunt / sweep) |

---

## GitHub token setup

`hunt` and `sweep` both need a token. Any one of these works:

1. **Env var** — `export GITHUB_TOKEN=ghp_...` (or `GH_TOKEN`)
2. **`gh` CLI** — if `gh auth status` says you're logged in, erinyes picks the token up automatically

**Required scopes:**

- Classic PAT: `public_repo` (read access to public repos) is enough
- Fine-grained PAT: `repository: read` for public repositories

**Rate limits:**

- Code search (hunt): 10 req/min — paced by `retrohunt.rate_limit_rps` per signature
- Core API (sweep tree walks): 5000 req/hour authenticated
- Repository search (sweep `--query`): 30 req/min

Fine-grained PATs with narrow scopes have smaller buckets. For heavy sweeps, use a classic PAT.

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

## Caching

Both `hunt` and `sweep` cache:

- **GitHub blobs** by their git sha — a repeat request for the same blob is free
- **Code-search responses** by query — reused for `--search-ttl` (default 1h)

Cache lives at the XDG cache dir (`$XDG_CACHE_HOME/erinyes` or `~/.cache/erinyes` on Linux, `~/Library/Caches/erinyes` on macOS). Override with `--cache-dir`. Disable with `--no-cache`.

Safe to delete the cache dir at any time — it rebuilds on next run.

---

## Sweep tuning for large targets

A sweep across an owner with many repos needs some care.

| Situation | Flag |
|---|---|
| You just want a list of what *would* be swept | `--dry-run` |
| First pass, keep API load low | `--limit 25` |
| You know only one signature's file patterns matter | Use `--signatures <narrow dir>` |
| A single repo has thousands of candidate files | Leave `--bulk-after 20` on — erinyes switches to tarball download |
| You hit a rate-limit wall | Lower `--workers`, bump `--search-ttl` |
| Repo is huge and you only care about one path | — not supported; sweep is tree-wide. Clone and `scan` instead. |

**Rule of thumb:** a signature's declared `retrohunt.rate_limit_rps` is the ceiling; `--rps` lets you lower it per-run but not raise it beyond what GitHub actually allows.

---

## Just recipes reference

Every command and dev task has a `just` recipe. From the repo root:

```bash
just                       # list every recipe
just build                 # build local binary
just install               # go install to $GOBIN
just build-all             # cross-compile linux/darwin/windows × amd64/arm64
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
just installer-check       # shellcheck the install/uninstall scripts
```

---

## Troubleshooting

**`401 Bad credentials` on hunt/sweep.**
Token is missing or wrong scope. `echo $GITHUB_TOKEN | wc -c` should be nonzero; `gh auth status` should say logged in.

**`403 API rate limit exceeded`.**
You hit the 10 req/min code-search cap or the 5000/hr core cap. Wait, or set `--rps` lower. Caching helps a lot on reruns.

**`signatures validate` fails on a brand-new YAML.**
Check [`docs/signature-format.md`](docs/signature-format.md) for the schema. `required: [id, version, description, file_patterns, indicators, threshold]`. Every `indicator.id` must be unique within the signature.

**Scan says "signatures: 0 loaded".**
Either the builtin catalog failed to compile in (rebuild) or `--signatures <path>` pointed at an empty / malformed directory.

**`erinyes: command not found` after `go install`.**
`$GOBIN` (or `$(go env GOPATH)/bin`) is not on your `PATH`. Add it to your shell profile.

**Sweep stops at exactly 1000 repos.**
That is GitHub's hard cap on `/search/repositories` results — not an erinyes limit. Narrow the query (`language:`, `stars:`, date ranges) to split the result set.

---

## Status and roadmap

Erinyes is actively being built. The signature catalog is deliberately small — every rule is derived from a confirmed sample. More families, more signatures, more rules land as the research corpus grows.

If you have a confirmed malicious sample and the YAML signature to go with it, see [`docs/contributing.md`](docs/contributing.md).
