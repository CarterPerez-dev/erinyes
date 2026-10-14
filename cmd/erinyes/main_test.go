// ©AngelaMos | 2026
// main_test.go

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func run(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	t.Setenv("ERINYES_CONFIG_DIR", t.TempDir())

	var out, errBuf bytes.Buffer
	cmd := newRootCommand()
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetArgs(args)

	code := exitOK
	if err := cmd.Execute(); err != nil {
		var ex *exitError
		if errors.As(err, &ex) {
			code = ex.code
		} else {
			code = exitToolError
		}
	}
	return out.String(), errBuf.String(), code
}

func TestScanMaliciousFixtureExitsOne(t *testing.T) {
	out, _, code := run(t, "scan", "../../testdata/known_malicious")

	if code != exitFound {
		t.Errorf("exit code = %d, want %d when a file is flagged", code, exitFound)
	}
	if !strings.Contains(out, "MALICIOUS (PyMapper)") {
		t.Errorf("output is missing a malicious verdict:\n%s", out)
	}
	if !strings.Contains(out, "Flagged: 3") {
		t.Errorf("output is missing the flagged count:\n%s", out)
	}
}

func TestScanBenignFixturesExitZero(t *testing.T) {
	out, _, code := run(t, "scan", "../../testdata/known_benign")
	if code != exitOK {
		t.Errorf("exit code = %d, want 0 for a clean tree", code)
	}
	if !strings.Contains(out, "Flagged: 0") {
		t.Errorf("output:\n%s", out)
	}
}

func TestScanMissingPathIsAToolError(t *testing.T) {
	_, _, code := run(t, "scan", filepath.Join(t.TempDir(), "nope"))
	if code != exitToolError {
		t.Errorf("exit code = %d, want %d", code, exitToolError)
	}
}

func TestScanJSONOutputToFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "out.json")
	_, _, code := run(t, "scan", "../../testdata/known_malicious", "--format", "json", "-o", path)
	if code != exitFound {
		t.Fatalf("exit code = %d", code)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("report was not written: %v", err)
	}
	var doc struct {
		Summary struct {
			Flagged int `json:"flagged"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}
	if doc.Summary.Flagged != 3 {
		t.Errorf("flagged = %d, want 3", doc.Summary.Flagged)
	}
}

func TestUnknownFormatIsRejected(t *testing.T) {
	_, _, code := run(t, "scan", "../../testdata/known_benign", "--format", "xml")
	if code != exitToolError {
		t.Errorf("exit code = %d, want %d", code, exitToolError)
	}
}

func TestVerifyKnownHash(t *testing.T) {
	out, _, code := run(t, "verify", "72d765b9be76ba841ec95548368bf9a67c9ea3823ae064d8d0beff66c4598bd9")
	if code != exitFound {
		t.Errorf("exit code = %d, want %d for a known-malicious hash", code, exitFound)
	}
	if !strings.Contains(out, "KNOWN MALICIOUS") {
		t.Errorf("output:\n%s", out)
	}
	if !strings.Contains(out, "kloxeld/xscrape") {
		t.Errorf("the hash label is missing:\n%s", out)
	}
}

func TestVerifyUnknownHash(t *testing.T) {
	out, _, code := run(t, "verify", strings.Repeat("0", 64))
	if code != exitOK {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out, "NOT IN CATALOG") {
		t.Errorf("output:\n%s", out)
	}
	if !strings.Contains(out, "not proof the file is clean") {
		t.Error("verify must not let a catalog miss read as an all-clear")
	}
}

func TestVerifyHashesAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.py")
	if err := os.WriteFile(path, []byte("print('hi')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, _, code := run(t, "verify", path)
	if code != exitOK {
		t.Errorf("exit code = %d", code)
	}
	if !strings.Contains(out, "sha256  ") {
		t.Errorf("output:\n%s", out)
	}
}

func TestVerifyRejectsGarbage(t *testing.T) {
	_, _, code := run(t, "verify", "not-a-hash-and-not-a-file")
	if code != exitToolError {
		t.Errorf("exit code = %d, want %d", code, exitToolError)
	}
}

func TestSignaturesList(t *testing.T) {
	out, _, code := run(t, "signatures", "list")
	if code != exitOK {
		t.Fatalf("exit code = %d", code)
	}
	for _, want := range []string{"pymapper-fs-loader", "PyMapper", "critical", "1 signature(s) loaded"} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q:\n%s", want, out)
		}
	}
}

func TestSignaturesShow(t *testing.T) {
	out, _, code := run(t, "signatures", "show", "pymapper-fs-loader")
	if code != exitOK {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(out, "id: pymapper-fs-loader") {
		t.Errorf("output:\n%s", out)
	}
	if !strings.Contains(out, "xor_decoder_lambda") {
		t.Error("show did not print the indicators")
	}
}

func TestSignaturesShowUnknownID(t *testing.T) {
	_, _, code := run(t, "signatures", "show", "does-not-exist")
	if code != exitToolError {
		t.Errorf("exit code = %d, want %d", code, exitToolError)
	}
}

func TestSignaturesValidateBuiltinCatalog(t *testing.T) {
	out, _, code := run(t, "signatures", "validate", "../../signatures")
	if code != exitOK {
		t.Fatalf("the shipped catalog does not validate (exit %d):\n%s", code, out)
	}
	if !strings.Contains(out, "OK    ") {
		t.Errorf("output:\n%s", out)
	}
	if strings.Contains(out, "WARN") {
		t.Errorf("the shipped catalog raises warnings:\n%s", out)
	}
}

func TestSignaturesValidateRejectsBadFile(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	body := "id: Bad-ID\nversion: 9\nfamily: X\nseverity: nope\nconfidence_threshold: 500\nfile_patterns: []\nindicators: []\n"
	if err := os.WriteFile(bad, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	out, _, code := run(t, "signatures", "validate", bad)
	if code != exitToolError {
		t.Errorf("exit code = %d, want %d", code, exitToolError)
	}
	for _, want := range []string{"FAIL", "must match", "version must be 1", "must be one of"} {
		if !strings.Contains(out, want) {
			t.Errorf("validate output is missing %q:\n%s", want, out)
		}
	}
}

func TestSignaturesValidateWarnsOnWeakSignature(t *testing.T) {
	dir := t.TempDir()
	body := "id: weak-sig\nversion: 1\nfamily: X\nseverity: low\nconfidence_threshold: 0\n" +
		"file_patterns: [\"*.py\"]\nindicators:\n  - name: a\n    weight: 0\n    type: literal\n    pattern: 'x'\n"
	path := filepath.Join(dir, "weak.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	out, _, code := run(t, "signatures", "validate", path)
	if code != exitOK {
		t.Fatalf("exit code = %d, warnings must not fail validation:\n%s", code, out)
	}
	for _, want := range []string{
		"every scanned file will be reported malicious",
		"weight 0 and cannot affect the score",
		"no retrohunt.github_queries",
		"no description",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("validate is missing the warning %q:\n%s", want, out)
		}
	}
}

func TestSignaturesOverrideFlag(t *testing.T) {
	dir := t.TempDir()
	body := "id: only-mine\nversion: 1\nfamily: Mine\nseverity: low\nconfidence_threshold: 10\n" +
		"file_patterns: [\"*.py\"]\nindicators:\n  - name: a\n    weight: 10\n    type: literal\n    pattern: 'zzz'\n"
	if err := os.WriteFile(filepath.Join(dir, "mine.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	out, _, code := run(t, "--signatures", dir, "signatures", "list")
	if code != exitOK {
		t.Fatalf("exit code = %d:\n%s", code, out)
	}
	if !strings.Contains(out, "only-mine") {
		t.Errorf("the override signature was not loaded:\n%s", out)
	}
	if strings.Contains(out, "pymapper-fs-loader") {
		t.Error("--signatures must replace the builtin catalog, not extend it")
	}
}

func TestVersionReportsCatalog(t *testing.T) {
	out, _, code := run(t, "version")
	if code != exitOK {
		t.Fatalf("exit code = %d", code)
	}
	for _, want := range []string{"erinyes", "catalog", "go ", "signatures 1 loaded"} {
		if !strings.Contains(out, want) {
			t.Errorf("version output is missing %q:\n%s", want, out)
		}
	}
}

func TestHuntDryRunMakesNoNetworkCalls(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	out, _, code := run(t, "hunt", "pymapper-fs-loader", "--dry-run")
	if code != exitOK {
		t.Fatalf("exit code = %d:\n%s", code, out)
	}
	if !strings.Contains(out, "language:python") {
		t.Errorf("dry run did not print the queries:\n%s", out)
	}
	if !strings.Contains(out, "10 req/min cap on code search") {
		t.Errorf("dry run did not state the rate cap:\n%s", out)
	}
}

func TestHuntUnknownSignature(t *testing.T) {
	_, _, code := run(t, "hunt", "no-such-signature", "--dry-run")
	if code != exitToolError {
		t.Errorf("exit code = %d, want %d", code, exitToolError)
	}
}
