<!-- ©AngelaMos | 2026 -->
<!-- signature-format.md -->

# Signature format

A signature is one YAML file describing one malware family's stage-1 artifact. Schema version is `1`.

```bash
erinyes signatures validate ./my-signature.yaml
```

Run that before you ship anything. Validation is strict by design: unknown keys are errors, not warnings.

---

## Full schema

```yaml
# ---- required ----
id: string                      # unique, kebab-case, how you name it on the CLI
version: int                    # schema version, currently 1
family: string                  # malware family name
severity: critical|high|medium|low
confidence_threshold: int       # 0-100, a score at or above this is MALICIOUS
file_patterns: [string]         # globs matched against the file's base name

indicators:                     # at least one
  - name: string                # unique within the signature
    weight: int                 # 0-100
    type: regex|literal         # ast is reserved and rejected in v1
    pattern: string

# ---- optional but expected ----
first_seen: YYYY-MM-DD
contributor: string
description: string
references: [string]

retrohunt:
  github_queries: [string]      # passed verbatim to GitHub code search
  rate_limit_rps: float         # fetch pacing, default 1.0

known_hashes:
  - sha256: string              # 64 hex characters
    label: string               # where this sample came from
    first_seen: YYYY-MM-DD
```

---

## Field notes

### `id`

Must match `^[a-z][a-z0-9-]*[a-z0-9]$`. Lowercase, kebab-case, no trailing dash. A duplicate `id` inside one catalog is a hard error, because silently shadowing somebody else's signature is how a catalog rots.

### `file_patterns`

Globs matched with Go's `filepath.Match` against the file's **base name**. A pattern containing `/` is additionally matched against the whole slash-normalized path. `"*"` matches everything.

During a directory walk, a file whose name matches no loaded signature's patterns is skipped and counted as skipped. A file named **explicitly** on the command line is run against every loaded signature regardless of its name, because if you point the tool at a file you want an answer about that file.

### `indicators`

Each indicator is scored once. Matching twenty times and matching once contribute the same weight; the count is reported as evidence only.

| `type` | Semantics |
|---|---|
| `regex` | Go RE2. No lookarounds, no backreferences. The default when `type` is omitted. |
| `literal` | Raw byte substring. Faster and unambiguous when there is nothing to generalize. |
| `ast` | Reserved. A signature using it is rejected in schema v1. |

Indicators run against raw bytes and are pure functions of those bytes. No indicator may read a file, resolve a path, or touch the network. The scanner reads the file exactly once and hands the same buffer to every indicator.

### `confidence_threshold`

| Score | Verdict |
|---|---|
| `>= confidence_threshold` | MALICIOUS |
| `>= confidence_threshold / 2` | SUSPICIOUS |
| below | clean |

**The rule that keeps a signature honest: no single indicator's weight should reach the threshold.** If one pattern can convict on its own, you have written a grep with extra steps, and the first benign file that happens to contain that pattern becomes a false positive you will defend in someone's issue tracker.

A threshold of `0` is accepted by the schema but warned about loudly, because it flags literally every file scanned.

### `retrohunt.github_queries`

Strings passed straight to GitHub's code search. Think about what is *searchable*: GitHub's index does not do regex, so these are necessarily more literal than your indicators. The division of labor is deliberate — queries cast a wide, cheap net, indicators make the decision.

Good practice is to pair one structural query that catches the family broadly with per-variant literals you have actually observed:

```yaml
github_queries:
  - '"bytes(v^k for v in a)" language:python'   # the shape, catches unknown operators
  - '"_rd9r1n" language:python'                 # a known operator's variable template
  - '"_spd980k" language:python'
```

`rate_limit_rps` paces file fetches. It cannot raise GitHub's hard cap of 10 code-search requests per minute, which the client enforces regardless.

### `known_hashes`

SHA-256 of files you have confirmed. A hash hit forces a MALICIOUS verdict but **does not** replace the indicator score.

That is deliberate. If a file you know is malware stops matching your indicators, the score drops to 0 and you can see it in the report while the verdict stays correct. That is your early warning that the operator changed their packer. A short-circuit on hash would hide exactly the signal you most need.

---

## Writing indicators that survive contact with an operator

Match **structure**, not identifiers. The PyMapper loader re-rolls its variable names per operator:

```python
_rd9r1n    = lambda a,k:bytes(v^k for v in a)
_spd980k   = lambda a,k:bytes(v^k for v in a)
_trtmhwg1q = lambda a,k:bytes(v^k for v in a)
```

A signature on `_rd9r1n` finds one campaign. A signature on the lambda's shape finds all three, plus operator four before anyone has seen them.

Tolerate whitespace at every joint. This pattern:

```
__import__\(\s*\w+\(\[\s*\d+
```

breaks the moment someone writes `__import__( _f( [1,2]`. This one does not:

```
__import__\(\s*\w+\(\s*\[\s*\d+
```

Both of the shipped signature's weakest patterns had exactly this hole until the indicator tests caught it. Write the negative tests first; they are where the evasions show up.

Avoid catastrophic patterns. RE2 has no backtracking so you cannot hang the scanner, but `(\s*\d+\s*,){80,}` across a megabyte of integers is still real work. Anchor on something cheap and distinctive where you can.

---

## Local and user signatures

```bash
erinyes scan ./repo --signatures ./my-sigs/     # replaces the builtin catalog entirely
```

Or drop files in `~/.config/erinyes/signatures/*.yaml` to **overlay** the builtin catalog. An overlay with the same `id` as a builtin signature replaces it; any other `id` is added alongside. This is how you patch a shipped signature locally without forking.

---

## Reserved identifiers

These IDs are reserved for signatures that are written but held back pending publication of the research. Do not reuse them:

- `pymapper-stage2-manual-mapper`
- `pymapper-stage3-proliv-pe`
- `pymapper-stage4-lold-config`
