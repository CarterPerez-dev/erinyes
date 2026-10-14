<!-- ©AngelaMos | 2026 -->
<!-- contributing.md -->

# Contributing

The most valuable contribution is a signature for a family nobody has written up yet. The second most valuable is a false positive.

---

## Contributing a signature

1. **Get samples.** More than one, ideally from more than one campaign. A signature written against a single file usually encodes that file's accidents rather than the family's structure.

2. **Find the invariants.** What survives across samples? The packer's control flow survives. Variable names usually do not. Constants sometimes do. Write indicators on what survives.

3. **Weight them so none can convict alone.** Set `confidence_threshold` so at least two independent indicators are required. If a single pattern is strong enough to decide, you wrote a grep.

4. **Write the negative fixtures first.** For each indicator, find real, legitimate code that trips it. Put it in `testdata/known_benign/` and add it to the table in that directory's README. If you cannot find any legitimate code that trips an indicator, you probably have not looked hard enough — and if you genuinely cannot, that indicator is a good one.

5. **Add retrohunt queries.** GitHub code search has no regex, so these are more literal than your indicators. Pair one structural query with the per-variant literals you have observed.

6. **Validate and test.**

   ```bash
   erinyes signatures validate ./signatures/my_family.yaml
   just check
   ```

7. **Never commit live malware.** Fixtures in `testdata/known_malicious/` are *synthetic*: structural reproductions with random bytes, no key material, no payload, no entrypoint call. They score identically to the real sample because the signature matches structure. If you hold real samples, point the opt-in regression at them locally:

   ```bash
   just corpus /path/to/your/samples
   ```

   Put their SHA-256 in `known_hashes` instead. A hash is an IOC; a working loader is a liability.

---

## Reporting a false positive

This is a bug report with a high bar for usefulness, and it is extremely welcome.

Include the file (or a minimal reduction of it), the output of:

```bash
erinyes scan ./the-file.py -v --format json
```

and what the file legitimately does. The fix is usually one of three things: tighten a pattern, lower a weight, or raise the threshold. All three are cheap. A signature that cries wolf gets turned off, and a tool that is turned off detects nothing.

---

## Code

```bash
just check     # fmt, vet, lint, test -race, validate the catalog
```

That is the bar. CI runs the same thing on Linux, macOS and Windows, plus shellcheck and an end-to-end install into a sandboxed HOME, plus SARIF schema validation.

House rules that are not negotiable:

- **New dependencies need a reason in the PR description.** The current count is four direct dependencies. Defenders audit this tool before running it on their infrastructure; every module is a question they have to answer.
- **`internal/scan` must never import a network package.** Scan mode being offline is a structural guarantee, not a default.
- **Indicators stay pure functions of bytes.** No file I/O, no path resolution, no network inside indicator evaluation.
- **No telemetry.** Not opt-in, not anonymous, not ever.

---

## What is out of scope

Sandboxing, emulation, disassembly, unpacking, vulnerability detection, and anything that executes a sample. Erinyes reads bytes and matches structure. Tools that do the other things already exist and are better at them.
