<!-- ©AngelaMos | 2026 -->
<!-- architecture.md -->

# Architecture

```
cmd/erinyes/            cobra CLI: root, scan, hunt, verify, signatures, version
internal/sig/           signature loading, validation, indicator matching
internal/scan/          the scan engine, scoring, verdicts
internal/gh/            GitHub client, rate limiting, on-disk cache
internal/report/        cli, json, markdown, sarif writers
internal/config/        ~/.config/erinyes/config.yaml
signatures/             the builtin catalog, compiled in with go:embed
testdata/               synthetic malicious fixtures and adversarial benign ones
```

Dependencies flow one way: `cmd` -> `report` -> `scan` -> `sig`. `gh` depends on nothing in this tree. Nothing depends on `cmd`.

---

## The data path

```
         scan                 hunt                      sweep
          |                     |                          |
   walk the filesystem   github CODE search      github REPOSITORY search
          |                     |                  or an owner's repo list
          |                     |                          |
          |             dedupe by (repo, path)      walk each git tree
          |                     |                          |
          |                     +----------+---------------+
          |                                |
          |                      blob cache lookup (git blob sha)
          |                                |
          |                    raw fetch -> verify blob sha
          |                       (fallback: blobs API)
          |                                |
          +-------------> bytes <----------+
                            |
                 sha256, then every matching
                  signature's indicators
                            |
                  sum weights -> verdict
                            |
         +----------+-------+--------+----------+
        cli       json          markdown      sarif
```

All three commands converge on the same `scan.ScanBytes`. A hunt or a sweep is a scan whose bytes came from GitHub, which is why the verdict for a file is identical whether you cloned the repo, hunted it, or swept it.

### hunt and sweep answer different questions

`hunt` asks the code index what it knows. It is cheap and wide, and it is bounded by what GitHub chose to index — on the PyMapper campaign, nine distinct structural queries all returned the same 12 files.

`sweep` reads repositories directly. It costs one tree call per repository plus one fetch per uncached candidate blob, and it sees files the index never covered. The same campaign yielded four more trojans when swept by its metadata pattern rather than its code.

Neither replaces the other. The index finds things you have no other handle on; the tree finds things the index forgot.

---

## Design decisions worth knowing

### Scan mode is offline, structurally

`internal/scan` imports no network package. Not "does not make requests by default" — it cannot. The GitHub client lives in a separate package that only the `hunt` command constructs. You can run `erinyes scan` on an airgapped host over an untrusted sample.

### Indicators are pure functions of bytes

`Indicator.Count([]byte) int` reads nothing, writes nothing, and mutates nothing. The scanner reads a file exactly once and hands the same buffer to every indicator. This is what makes the concurrent path safe, and it means a signature can never be a vector for anything.

### Known hashes are additive, not a short circuit

The specification originally had a hash hit return early with a score of 100. It does not, for one reason: a known sample that scores 0 on indicators is a signature that has gone stale, and that is exactly the event you need to see. The verdict is forced to MALICIOUS; the score stays true. The corpus regression test asserts both.

### Concurrency has two regimes

Per file: indicators run sequentially below 50KB and one-goroutine-per-indicator above it. Below that size the goroutine overhead costs more than the regex work. A test asserts both paths produce byte-identical hits on the same input.

Per tree: a worker pool sized to `runtime.NumCPU()`, fed by a single walker. Measured at roughly 147,000 files per second on a 14700KF, against a spec target of 1,000.

### The GitHub cache is keyed by git blob SHA, not content SHA-256

The specification said SHA-256. The blob SHA is better for one decisive reason: **code search tells you the blob SHA before you download anything.** A content-SHA cache can only deduplicate after you have already paid for the request. A blob-SHA cache turns a repeat hunt into zero API calls, which is the difference between 41 seconds and 38 milliseconds on the reference hunt.

It also gives verification for free. We fetch from `raw.githubusercontent.com`, which serves a mutable branch ref, then recompute the blob SHA and compare it to what search reported. On mismatch, the client falls back to the git blobs API, which is content-addressed and immutable. You always get the exact bytes search matched, which matters when the output is going into a paper.

### Rate limiting is per-resource

GitHub's code search allows 10 requests per minute; the core API allows 5,000 per hour. One limiter cannot serve both. Search is floored at a 6-second interval regardless of what a signature declares; file fetches use the signature's `rate_limit_rps`. `X-RateLimit-*` headers are parsed on every response and the client sleeps until reset when the remaining quota drops below five.

Backoff is split by cause: a secondary rate limit backs off from 60 seconds, a transient 5xx backs off from 2 seconds. Treating a flaky gateway like a rate limit wastes a minute for nothing.

### The CLI hides clean files

A 10,000 file tree with one hit should not print 9,999 lines of CLEAN. Default output shows flagged and suspicious files and reports the hidden count so you know elision happened. `-v` shows everything. JSON and SARIF always contain every result; the elision is a presentation choice, not a data one.

### Exit codes are the CI contract

`0` clean, `1` flagged, `2` tool error, `3` rate limited. A tool error and a detection must never share a code, or a broken signature file reads as a clean scan.
