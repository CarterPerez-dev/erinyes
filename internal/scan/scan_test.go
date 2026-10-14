// ©AngelaMos | 2026
// scan_test.go

package scan_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CarterPerez-dev/erinyes/internal/scan"
	"github.com/CarterPerez-dev/erinyes/internal/sig"
)

const maliciousDir = "../../testdata/known_malicious"
const benignDir = "../../testdata/known_benign"

func builtinCatalog(t *testing.T) *sig.Catalog {
	t.Helper()
	return builtinCatalogB(t)
}

func builtinCatalogB(tb testing.TB) *sig.Catalog {
	tb.Helper()
	cat := sig.NewCatalog()
	if err := sig.LoadBuiltin(cat); err != nil {
		tb.Fatalf("LoadBuiltin() = %v", err)
	}
	return cat
}

func pymapper(t *testing.T) *sig.Signature {
	t.Helper()
	s, ok := builtinCatalog(t).Get("pymapper-fs-loader")
	if !ok {
		t.Fatal("builtin catalog has no pymapper-fs-loader")
	}
	return s
}

func TestKnownMaliciousFixturesAreFlagged(t *testing.T) {
	scanner := scan.New(builtinCatalog(t))
	results, summary, err := scanner.ScanPath(context.Background(), maliciousDir)
	if err != nil {
		t.Fatalf("ScanPath() = %v", err)
	}
	if summary.Scanned == 0 {
		t.Fatal("no fixtures were scanned")
	}
	if summary.Flagged != summary.Scanned {
		t.Errorf("flagged %d of %d fixtures, want all of them", summary.Flagged, summary.Scanned)
	}
	for _, r := range results {
		if r.Verdict != scan.VerdictMalicious {
			t.Errorf("%s: verdict = %s, want malicious", r.FilePath, r.Verdict)
		}
		if r.TotalScore != 140 {
			t.Errorf("%s: score = %d, want 140 (the score every observed PyMapper stage-1 produces)", r.FilePath, r.TotalScore)
		}
		if r.Signature != "pymapper-fs-loader" {
			t.Errorf("%s: signature = %q", r.FilePath, r.Signature)
		}
	}
}

func TestKnownBenignFixturesAreNeverFlagged(t *testing.T) {
	scanner := scan.New(builtinCatalog(t))
	results, summary, err := scanner.ScanPath(context.Background(), benignDir)
	if err != nil {
		t.Fatalf("ScanPath() = %v", err)
	}
	if summary.Flagged != 0 {
		t.Errorf("flagged %d benign fixtures, want 0", summary.Flagged)
	}

	want := map[string]scan.Verdict{
		"simple_xor_helper.py": scan.VerdictSuspicious,
		"crc_table.py":         scan.VerdictClean,
		"chunked_cipher.py":    scan.VerdictClean,
		"plugin_registry.py":   scan.VerdictClean,
	}
	for _, r := range results {
		base := filepath.Base(r.FilePath)
		expected, tracked := want[base]
		if !tracked {
			t.Errorf("untracked benign fixture %s: add it to the table in testdata/known_benign/README.md", base)
			continue
		}
		if r.Verdict != expected {
			t.Errorf("%s: verdict = %s, want %s", base, r.Verdict, expected)
		}
		delete(want, base)
	}
	for missing := range want {
		t.Errorf("benign fixture %s was not scanned", missing)
	}
}

func TestNoSingleIndicatorCanFlagAFile(t *testing.T) {
	s := pymapper(t)
	for i := range s.Indicators {
		if s.Indicators[i].Weight >= s.ConfidenceThreshold {
			t.Errorf("indicator %q carries weight %d which alone clears the threshold of %d",
				s.Indicators[i].Name, s.Indicators[i].Weight, s.ConfidenceThreshold)
		}
	}
}

func TestScorerBoundaries(t *testing.T) {
	s := pymapper(t)
	threshold := s.ConfidenceThreshold
	half := s.SuspiciousThreshold()

	cases := []struct {
		score int
		want  scan.Verdict
	}{
		{0, scan.VerdictClean},
		{half - 1, scan.VerdictClean},
		{half, scan.VerdictSuspicious},
		{threshold - 1, scan.VerdictSuspicious},
		{threshold, scan.VerdictMalicious},
		{threshold + 1, scan.VerdictMalicious},
		{1000, scan.VerdictMalicious},
	}
	for _, tc := range cases {
		if got := scan.Classify(tc.score, s); got != tc.want {
			t.Errorf("Classify(%d) = %s, want %s (threshold %d, half %d)", tc.score, got, tc.want, threshold, half)
		}
	}
}

func TestScoreSumsWeightsOncePerIndicator(t *testing.T) {
	hits := []scan.IndicatorHit{
		{Indicator: "a", MatchCount: 1, Weight: 40},
		{Indicator: "b", MatchCount: 99, Weight: 25},
	}
	if got := scan.Score(hits); got != 65 {
		t.Errorf("Score() = %d, want 65: match count must not multiply the weight", got)
	}
	if got := scan.Score(nil); got != 0 {
		t.Errorf("Score(nil) = %d, want 0", got)
	}
}

func TestKnownHashForcesMaliciousAndKeepsEvidence(t *testing.T) {
	body := `
id: hash-only
version: 1
family: Hashes
severity: critical
confidence_threshold: 50
file_patterns: ["*.py"]
indicators:
  - name: never-fires
    weight: 50
    type: literal
    pattern: 'this string is absent'
known_hashes:
  - sha256: %s
    label: a sample whose packer we have already seen
`
	data := []byte("print('harmless')\n")
	sum := sha256.Sum256(data)
	s, err := sig.Parse([]byte(fmt.Sprintf(body, hex.EncodeToString(sum[:]))), "test.yaml")
	if err != nil {
		t.Fatalf("Parse() = %v", err)
	}

	res := scan.New(sig.NewCatalog()).ScanBytes("sample.py", data, s)
	if res.Verdict != scan.VerdictMalicious {
		t.Errorf("verdict = %s, want malicious for a known hash", res.Verdict)
	}
	if res.KnownHash == "" {
		t.Error("KnownHash label is empty")
	}
	if res.TotalScore != 0 {
		t.Errorf("TotalScore = %d, want the true indicator score of 0 so signature rot stays visible", res.TotalScore)
	}
}

func TestScanBytesComputesHashAndSize(t *testing.T) {
	data := []byte("print('hello')\n")
	sum := sha256.Sum256(data)
	res := scan.New(sig.NewCatalog()).ScanBytes("x.py", data, pymapper(t))

	if res.FileSHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("FileSHA256 = %q", res.FileSHA256)
	}
	if res.FileSize != int64(len(data)) {
		t.Errorf("FileSize = %d, want %d", res.FileSize, len(data))
	}
	if res.Threshold != pymapper(t).ConfidenceThreshold {
		t.Errorf("Threshold = %d", res.Threshold)
	}
}

func TestConcurrentAndSequentialIndicatorPathsAgree(t *testing.T) {
	sample, err := os.ReadFile(filepath.Join(maliciousDir, "pymapper_template_rd9r1n.py"))
	if err != nil {
		t.Fatal(err)
	}
	if len(sample) >= 50<<10 {
		t.Fatalf("fixture grew to %d bytes and no longer exercises the sequential path", len(sample))
	}

	padded := append(append([]byte{}, sample...), []byte("\n# "+strings.Repeat("x", 50<<10))...)
	s := pymapper(t)
	scanner := scan.New(builtinCatalog(t))

	small := scanner.ScanBytes("small.py", sample, s)
	big := scanner.ScanBytes("big.py", padded, s)

	if small.TotalScore != 140 || big.TotalScore != 140 {
		t.Errorf("scores differ across code paths: sequential %d, concurrent %d, want 140 for both", small.TotalScore, big.TotalScore)
	}
	if len(small.Hits) != len(big.Hits) {
		t.Fatalf("hit counts differ: sequential %d, concurrent %d", len(small.Hits), len(big.Hits))
	}
	for i := range small.Hits {
		if small.Hits[i] != big.Hits[i] {
			t.Errorf("hit %d differs: sequential %+v, concurrent %+v", i, small.Hits[i], big.Hits[i])
		}
	}
}

func TestOversizeFilesAreSkippedNotErrored(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "huge.py")
	if err := os.WriteFile(big, []byte(strings.Repeat("x", 4096)), 0o644); err != nil {
		t.Fatal(err)
	}

	scanner := scan.New(builtinCatalog(t), scan.WithMaxFileSize(1024))
	_, summary, err := scanner.ScanPath(context.Background(), dir)
	if err != nil {
		t.Fatalf("ScanPath() = %v", err)
	}
	if summary.Errors != 0 {
		t.Errorf("Errors = %d, want 0", summary.Errors)
	}
	if summary.Skipped == 0 {
		t.Error("Skipped = 0, want the oversize file counted as skipped")
	}
	if summary.Scanned != 0 {
		t.Errorf("Scanned = %d, want 0", summary.Scanned)
	}
}

func TestNonMatchingExtensionsAreSkipped(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.py", "b.js", "c.txt", "d.exe"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("noop\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_, summary, err := scan.New(builtinCatalog(t)).ScanPath(context.Background(), dir)
	if err != nil {
		t.Fatalf("ScanPath() = %v", err)
	}
	if summary.Scanned != 1 {
		t.Errorf("Scanned = %d, want 1: only *.py matches the builtin catalog", summary.Scanned)
	}
	if summary.Skipped != 3 {
		t.Errorf("Skipped = %d, want 3", summary.Skipped)
	}
}

func TestGitDirectoryIsNotWalked(t *testing.T) {
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "hook.py"), []byte("noop\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, summary, err := scan.New(builtinCatalog(t)).ScanPath(context.Background(), dir)
	if err != nil {
		t.Fatalf("ScanPath() = %v", err)
	}
	if summary.Scanned != 0 {
		t.Errorf("Scanned = %d, want 0: .git must not be walked", summary.Scanned)
	}
}

func TestSingleFileIsScannedEvenWithoutAPatternMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "loader.txt")
	sample, err := os.ReadFile(filepath.Join(maliciousDir, "pymapper_template_spd980k.py"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, sample, 0o644); err != nil {
		t.Fatal(err)
	}

	results, summary, err := scan.New(builtinCatalog(t)).ScanPath(context.Background(), path)
	if err != nil {
		t.Fatalf("ScanPath() = %v", err)
	}
	if summary.Flagged != 1 {
		t.Fatalf("Flagged = %d, want 1: an explicitly named file runs every signature", summary.Flagged)
	}
	if results[0].TotalScore != 140 {
		t.Errorf("score = %d, want 140", results[0].TotalScore)
	}
}

func TestScanPathCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := scan.New(builtinCatalog(t)).ScanPath(ctx, maliciousDir)
	if err == nil {
		t.Error("ScanPath() with a cancelled context returned no error")
	}
}

func TestVerdictJSONRoundTrip(t *testing.T) {
	for _, v := range []scan.Verdict{scan.VerdictClean, scan.VerdictSuspicious, scan.VerdictMalicious} {
		data, err := v.MarshalJSON()
		if err != nil {
			t.Fatalf("MarshalJSON() = %v", err)
		}
		var back scan.Verdict
		if err := back.UnmarshalJSON(data); err != nil {
			t.Fatalf("UnmarshalJSON(%s) = %v", data, err)
		}
		if back != v {
			t.Errorf("round trip changed %s into %s", v, back)
		}
	}
}

func TestRealCorpusRegression(t *testing.T) {
	dir := os.Getenv("ERINYES_CORPUS")
	if dir == "" {
		t.Skip("set ERINYES_CORPUS to a directory of real stage-1 samples to run this regression")
	}
	results, summary, err := scan.New(builtinCatalog(t)).ScanPath(context.Background(), dir)
	if err != nil {
		t.Fatalf("ScanPath() = %v", err)
	}
	if summary.Scanned == 0 {
		t.Fatalf("ERINYES_CORPUS=%s contained no scannable files", dir)
	}
	for _, r := range results {
		if r.Verdict != scan.VerdictMalicious {
			t.Errorf("%s: verdict = %s, want malicious", r.FilePath, r.Verdict)
		}
		if r.TotalScore < 140 {
			t.Errorf("%s: score = %d, want at least 140", r.FilePath, r.TotalScore)
		}
		if r.KnownHash == "" {
			t.Errorf("%s (sha256 %s) is not in the shipped known_hashes list", r.FilePath, r.FileSHA256)
		}
	}
	t.Logf("%d real samples, %d flagged", summary.Scanned, summary.Flagged)
}
