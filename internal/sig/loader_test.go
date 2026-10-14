// ©AngelaMos | 2026
// loader_test.go

package sig_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CarterPerez-dev/erinyes/internal/sig"
)

const minimal = `
id: test-signature
version: 1
family: TestFamily
severity: high
confidence_threshold: 50
file_patterns: ["*.py"]
indicators:
  - name: alpha
    weight: 30
    type: regex
    pattern: 'alpha\d+'
  - name: beta
    weight: 30
    type: literal
    pattern: 'beta-literal'
`

func parse(t *testing.T, body string) (*sig.Signature, error) {
	t.Helper()
	return sig.Parse([]byte(body), "test.yaml")
}

func mustParse(t *testing.T, body string) *sig.Signature {
	t.Helper()
	s, err := parse(t, body)
	if err != nil {
		t.Fatalf("Parse() returned error: %v", err)
	}
	return s
}

func TestParseMinimal(t *testing.T) {
	s := mustParse(t, minimal)

	if s.ID != "test-signature" {
		t.Errorf("ID = %q, want test-signature", s.ID)
	}
	if s.MaxScore() != 60 {
		t.Errorf("MaxScore() = %d, want 60", s.MaxScore())
	}
	if s.SuspiciousThreshold() != 25 {
		t.Errorf("SuspiciousThreshold() = %d, want 25", s.SuspiciousThreshold())
	}
	if s.RateLimitRPS() != 1.0 {
		t.Errorf("RateLimitRPS() = %v, want the 1.0 default", s.RateLimitRPS())
	}
	if s.Label() != "test-signature@1" {
		t.Errorf("Label() = %q", s.Label())
	}
}

func TestValidationRejects(t *testing.T) {
	cases := []struct {
		name string
		edit func(string) string
		want string
	}{
		{"uppercase id", func(b string) string { return strings.Replace(b, "id: test-signature", "id: TestSignature", 1) }, "must match"},
		{"trailing dash id", func(b string) string { return strings.Replace(b, "id: test-signature", "id: test-", 1) }, "must match"},
		{"wrong schema version", func(b string) string { return strings.Replace(b, "version: 1", "version: 2", 1) }, "version must be 1"},
		{"threshold over 100", func(b string) string {
			return strings.Replace(b, "confidence_threshold: 50", "confidence_threshold: 101", 1)
		}, "must be in [0, 100]"},
		{"negative threshold", func(b string) string {
			return strings.Replace(b, "confidence_threshold: 50", "confidence_threshold: -1", 1)
		}, "must be in [0, 100]"},
		{"unreachable threshold", func(b string) string {
			return strings.Replace(b, "confidence_threshold: 50", "confidence_threshold: 95", 1)
		}, "can never fire"},
		{"bad severity", func(b string) string { return strings.Replace(b, "severity: high", "severity: spicy", 1) }, "must be one of"},
		{"no file patterns", func(b string) string { return strings.Replace(b, `file_patterns: ["*.py"]`, "file_patterns: []", 1) }, "at least one file_patterns"},
		{"no family", func(b string) string { return strings.Replace(b, "family: TestFamily", `family: ""`, 1) }, "family is required"},
		{"uncompilable regex", func(b string) string { return strings.Replace(b, `pattern: 'alpha\d+'`, `pattern: 'alpha(\d+'`, 1) }, "does not compile as RE2"},
		{"lookahead is not RE2", func(b string) string { return strings.Replace(b, `pattern: 'alpha\d+'`, `pattern: '(?=alpha)'`, 1) }, "does not compile as RE2"},
		{"ast type reserved", func(b string) string { return strings.Replace(b, "type: regex", "type: ast", 1) }, "reserved and not implemented"},
		{"unknown indicator type", func(b string) string { return strings.Replace(b, "type: regex", "type: yara", 1) }, "unknown type"},
		{"unknown field", func(b string) string { return b + "\nmystery_field: 7\n" }, "field mystery_field not found"},
		{"short hash", func(b string) string {
			return b + "\nknown_hashes:\n  - sha256: abc123\n    label: too short\n"
		}, "not a 64-character hex"},
		{"duplicate indicator name", func(b string) string {
			return strings.Replace(b, "  - name: beta", "  - name: alpha", 1)
		}, "duplicate indicator name"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse(t, tc.edit(minimal))
			if err == nil {
				t.Fatalf("Parse() accepted an invalid signature, want error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Parse() error = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestValidationAcceptsThresholdZeroButFlags(t *testing.T) {
	s := mustParse(t, strings.Replace(minimal, "confidence_threshold: 50", "confidence_threshold: 0", 1))
	if s.ConfidenceThreshold != 0 {
		t.Fatalf("ConfidenceThreshold = %d", s.ConfidenceThreshold)
	}
}

func TestMatchesPath(t *testing.T) {
	s := mustParse(t, minimal)
	cases := map[string]bool{
		"fs.py":                true,
		"pkg/sub/fs.py":        true,
		"/abs/path/fs.py":      true,
		"fs.pyc":               false,
		"fs.js":                false,
		"py":                   false,
		"dir.py/notpython.txt": false,
	}
	for path, want := range cases {
		if got := s.MatchesPath(path); got != want {
			t.Errorf("MatchesPath(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestMatchesPathWildcard(t *testing.T) {
	s := mustParse(t, strings.Replace(minimal, `file_patterns: ["*.py"]`, `file_patterns: ["*"]`, 1))
	if !s.MatchesPath("anything.exe") {
		t.Error(`file_patterns ["*"] should match every path`)
	}
}

func TestKnownHashLookupIsCaseInsensitive(t *testing.T) {
	body := minimal + `
known_hashes:
  - sha256: 72D765B9BE76BA841EC95548368BF9A67C9EA3823AE064D8D0BEFF66C4598BD9
    label: upper case in the yaml
`
	s := mustParse(t, body)
	kh, ok := s.MatchesKnownHash("72d765b9be76ba841ec95548368bf9a67c9ea3823ae064d8d0beff66c4598bd9")
	if !ok {
		t.Fatal("MatchesKnownHash() did not match a differently cased digest")
	}
	if kh.Label != "upper case in the yaml" {
		t.Errorf("Label = %q", kh.Label)
	}
	if _, ok := s.MatchesKnownHash(strings.Repeat("0", 64)); ok {
		t.Error("MatchesKnownHash() matched an unknown digest")
	}
}

func TestCatalogRejectsDuplicateID(t *testing.T) {
	cat := sig.NewCatalog()
	if err := cat.Add(mustParse(t, minimal)); err != nil {
		t.Fatalf("first Add() = %v", err)
	}
	err := cat.Add(mustParse(t, minimal))
	if err == nil {
		t.Fatal("Add() accepted a duplicate id")
	}
	if !strings.Contains(err.Error(), "duplicate signature id") {
		t.Errorf("Add() error = %v", err)
	}
}

func TestCatalogReplaceOverlaysUserSignature(t *testing.T) {
	cat := sig.NewCatalog()
	if err := cat.Add(mustParse(t, minimal)); err != nil {
		t.Fatalf("Add() = %v", err)
	}
	cat.Replace(mustParse(t, strings.Replace(minimal, "family: TestFamily", "family: Overridden", 1)))

	if cat.Len() != 1 {
		t.Fatalf("Len() = %d, want 1 after Replace", cat.Len())
	}
	s, _ := cat.Get("test-signature")
	if s.Family != "Overridden" {
		t.Errorf("Family = %q, want Overridden", s.Family)
	}
}

func TestLoadBuiltinCatalog(t *testing.T) {
	cat := sig.NewCatalog()
	if err := sig.LoadBuiltin(cat); err != nil {
		t.Fatalf("LoadBuiltin() = %v", err)
	}
	if cat.Len() == 0 {
		t.Fatal("LoadBuiltin() loaded no signatures")
	}
	s, ok := cat.Get("pymapper-fs-loader")
	if !ok {
		t.Fatal("builtin catalog is missing pymapper-fs-loader")
	}
	if s.Family != "PyMapper" {
		t.Errorf("Family = %q", s.Family)
	}
	if len(s.Retrohunt.GitHubQueries) == 0 {
		t.Error("pymapper-fs-loader declares no retrohunt queries")
	}
	if len(s.KnownHashes) == 0 {
		t.Error("pymapper-fs-loader ships no known hashes")
	}
}

func TestLoadOverrideDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "custom.yaml"), []byte(minimal), 0o644); err != nil {
		t.Fatal(err)
	}
	cat, err := sig.Load(sig.LoadOptions{Override: dir})
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if cat.Len() != 1 {
		t.Fatalf("Len() = %d, want only the override signature", cat.Len())
	}
	if _, ok := cat.Get("pymapper-fs-loader"); ok {
		t.Error("an override directory must not also load the builtin catalog")
	}
}

func TestLoadUserDirOverlaysBuiltin(t *testing.T) {
	dir := t.TempDir()
	overlay := strings.Replace(minimal, "id: test-signature", "id: pymapper-fs-loader", 1)
	overlay = strings.Replace(overlay, "family: TestFamily", "family: LocallyPatched", 1)
	if err := os.WriteFile(filepath.Join(dir, "patch.yaml"), []byte(overlay), 0o644); err != nil {
		t.Fatal(err)
	}

	cat, err := sig.Load(sig.LoadOptions{UserDir: dir})
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	s, ok := cat.Get("pymapper-fs-loader")
	if !ok {
		t.Fatal("overlay removed the builtin signature")
	}
	if s.Family != "LocallyPatched" {
		t.Errorf("Family = %q, want the user overlay to win", s.Family)
	}
}

func TestLoadMissingUserDirIsNotAnError(t *testing.T) {
	cat, err := sig.Load(sig.LoadOptions{UserDir: filepath.Join(t.TempDir(), "does-not-exist")})
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if cat.Len() == 0 {
		t.Error("builtin catalog should still load when the user dir is absent")
	}
}
