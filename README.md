<!-- ©AngelaMos | 2026 -->
<!-- README.md -->

# Erinyes

**Erinyes hunts obfuscated malware hiding in open source.**

It applies a catalog of YAML signatures to source files and tells you, with evidence, whether a file is a packed loader wearing a legitimate project's clothes. Point it at a checkout, or point it at all of GitHub.

Named after the Greek goddesses of vengeance who hunted down crimes human law could not touch. That is the job description.

```
SCORE  VERDICT                       FILE
------------------------------------------------------------------------------
  140  MALICIOUS (PyMapper, known)   kloxeld/xscrape:xscrape/fs.py
         + known hash  kloxeld/xscrape xscrape/fs.py (operator A template _rd9r1n)
         + xor_decoder_lambda x1  (+40)
         + import_via_xor_decoder x4  (+25)
         + rolling_xor_checksum x5  (+30)
         + hmac_keystream_block x1  (+20)
         + embedded_encrypted_blob x16  (+25)

Scanned: 41 files
Flagged: 1
Signatures: pymapper-fs-loader@1
Elapsed: 2ms
```

---

## What this is, and what it is not

Erinyes is not a vulnerability scanner. CodeQL, Semgrep and Snyk look for bugs in code that is trying to be correct. Erinyes looks for code that is trying to be *invisible*: a 28KB "logger.py" whose whole body is a one-line XOR lambda, four decoded imports, and sixteen arrays of integers that unpack into a reflective PE loader.

Different threat model, different tool.

It is also not a sandbox, not a disassembler, not an AV engine, and not an incident-response platform. It reads bytes, matches structure, scores, and reports. That is the entire scope, on purpose.

**Scan mode makes zero network calls.** Ever. You can run it on an airgapped box over a sample you do not trust.

---

## Install

```bash
curl -fsSL https://angelamos.com/erinyes/install.sh | bash
```

One command, from nothing to `erinyes` on your PATH. It prefers a verified release binary and falls back to building from source, installing Go first if you do not have it.

Other ways in:

```bash
go install github.com/CarterPerez-dev/erinyes/cmd/erinyes@latest   # if you already have Go
git clone https://github.com/CarterPerez-dev/erinyes && cd erinyes && just build
```

Removing it is the mirror image:

```bash
curl -fsSL https://angelamos.com/erinyes/uninstall.sh | bash
```

---

## Use

### Scan something local

```bash
erinyes scan ./suspicious-repo
erinyes scan ./one_file.py
erinyes scan ~/src --format sarif --output results.sarif
```

Walks the tree, applies every signature whose `file_patterns` match, prints one row per file. Clean files are hidden unless you pass `-v`. Exits `1` if anything scored at or above its signature's threshold, so it drops straight into CI.

### Retrohunt GitHub

```bash
export GITHUB_TOKEN=...            # or just be logged into `gh`
erinyes hunt pymapper-fs-loader
erinyes hunt all --format markdown --output hunt.md
erinyes hunt pymapper-fs-loader --limit 100 --dry-run
```

Runs the signature's declared code-search queries, pulls every result, scans it locally. GitHub caps code search at 10 requests per minute, so a wide hunt is paced rather than fast — the tool respects that cap instead of getting your token throttled.

Every blob it downloads is cached forever, keyed by its git blob SHA. The second run of the same hunt costs zero API calls:

```
0 api call(s), 0 raw fetch(es), 14 cache hit(s)
```

### Check a hash

```bash
erinyes verify 72d765b9be76ba841ec95548368bf9a67c9ea3823ae064d8d0beff66c4598bd9
erinyes verify ./downloaded.py
```

A miss is not an all-clear and the tool says so out loud.

### Inspect the catalog

```bash
erinyes signatures list
erinyes signatures show pymapper-fs-loader
erinyes signatures validate ./my-signatures/
```

---

## How scoring works

Every signature is a set of weighted indicators. A file's score is the sum of the weights of the indicators that matched *at least once* — match count is reported as evidence but never multiplies the weight, because a packer that emits sixteen blobs is not sixteen times more malicious than one that emits one.

| Score | Verdict |
|---|---|
| `>= confidence_threshold` | **MALICIOUS** |
| `>= confidence_threshold / 2` | **SUSPICIOUS** |
| below that | clean |

The design rule that matters: **no single indicator may clear the threshold on its own.** `pymapper-fs-loader` has a threshold of 60 and its heaviest indicator is worth 40. A file with a bare XOR lambda and nothing else lands in the suspicious band, which is the honest answer. There is a test that fails the build if anyone ever adds an indicator heavy enough to convict alone.

A known-malicious hash forces a MALICIOUS verdict but **does not** replace the score. If a file we know is malware stops matching the indicators, you need to see that — it means the operator re-rolled their packer and your signature is going stale.

---

## Writing a signature

Signatures are YAML. The full schema is in [docs/signature-format.md](docs/signature-format.md); here is the shape:

```yaml
id: my-loader
version: 1
family: SomeFamily
severity: critical
confidence_threshold: 60
file_patterns: ["*.py"]

indicators:
  - name: xor_decoder_lambda
    weight: 40
    type: regex
    pattern: 'lambda\s+\w+\s*,\s*\w+\s*:\s*bytes\(\s*\w+\s*\^\s*\w+\s+for\s+\w+\s+in\s+\w+\s*\)'

retrohunt:
  github_queries:
    - '"bytes(v^k for v in a)" language:python'

known_hashes:
  - sha256: 72d765b9...
    label: where this sample came from
```

Lint it before you ship it:

```bash
erinyes signatures validate ./my-signature.yaml
```

Validation is strict on purpose: unknown YAML keys are errors, patterns must compile as Go RE2, and a signature whose weights cannot physically reach its own threshold is rejected rather than silently never firing.

Drop user signatures in `~/.config/erinyes/signatures/*.yaml` and they overlay the builtin catalog. Same `id` replaces the builtin one.

---

## Why the indicators match structure, not strings

The PyMapper stage-1 loader assigns itself a random variable template per operator. Three seen in the wild so far:

```python
_rd9r1n   = lambda a,k:bytes(v^k for v in a)     # operator A
_spd980k  = lambda a,k:bytes(v^k for v in a)     # operator B
_trtmhwg1q= lambda a,k:bytes(v^k for v in a)     # operator ?
```

Grepping for `_rd9r1n` finds one operator's campaign. Matching the *shape* of the decoder finds all of them, including operators whose template nobody has seen yet. Every shipped indicator is anchored on structure for exactly this reason, and the patterns tolerate inserted whitespace so that reformatting the payload is not a one-keystroke evasion.

**Measured on the current catalog:** 14 known-malicious samples across 3 operator templates all score 140. 1,314 benign Python files across the standard library, system packages and adversarially-chosen near-misses score 0, except for four fixtures deliberately built to trip exactly one indicator each.

---

## Output formats

| Format | Flag | For |
|---|---|---|
| CLI | *(default)* | reading it yourself |
| JSON | `--format json` | piping into anything |
| Markdown | `--format markdown` | reports and papers |
| SARIF 2.1.0 | `--format sarif` | GitHub code scanning, Codacy, Sonar |

The SARIF output validates against the official OASIS 2.1.0 schema and anchors local paths to `SRCROOT` with `originalUriBaseIds`, so GitHub's Security tab resolves them correctly.

```bash
erinyes scan . --format sarif --output erinyes.sarif
gh api -X POST /repos/OWNER/REPO/code-scanning/sarifs \
  -f commit_sha="$(git rev-parse HEAD)" -f ref=refs/heads/main \
  -f sarif="$(gzip -c erinyes.sarif | base64 -w0)"
```

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | nothing at or above threshold |
| `1` | something was flagged |
| `2` | tool error (bad signature, auth failure, unreadable path) |
| `3` | rate limited, gave up |

---

## Configuration

Optional, at `~/.config/erinyes/config.yaml` (`%APPDATA%\erinyes` on Windows):

```yaml
format: cli
cache_dir: ~/.cache/erinyes
signatures_dir: ~/.config/erinyes/signatures
no_color: false
```

Unknown keys are rejected rather than ignored, so a typo tells you instead of silently doing nothing. `XDG_CONFIG_HOME` and `XDG_CACHE_HOME` are respected.

---

## Development

```bash
just            # list recipes
just build      # single binary
just check      # fmt, vet, lint, test with -race
just bench      # scan throughput
just build-all  # linux/darwin amd64+arm64, windows amd64
just package    # tarballs, zip, checksums.txt
```

Two fixture sets back the test suite:

- `testdata/known_malicious/` — **synthetic** structural reproductions of the stage-1 loader, one per observed operator template. They reproduce the packer's shape with random bytes: no key material, no payload, no entrypoint. They score 140, same as the real thing. Live malware is deliberately not committed to this repository.
- `testdata/known_benign/` — files that each trip exactly one indicator on purpose, proving no single indicator can convict.

If you hold a corpus of real samples, point the opt-in regression at it:

```bash
just corpus /path/to/real/samples
```

It asserts every sample is flagged, scores at least 140, and is covered by a shipped `known_hashes` entry — which is how you catch a signature going stale against a live family.

---

## Provenance

The seed signature comes from Operation CLAUDEIUS, a full-chain reverse engineering of the PyMapper malware-as-a-service platform and its five operators. The stage-1 loader it detects was found in 14 trojanized GitHub repositories masquerading as AI tooling, crypto bots, pentest PoCs and general developer utilities.

---

## License

AGPL-3.0. See [LICENSE](LICENSE).
