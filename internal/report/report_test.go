// ©AngelaMos | 2026
// report_test.go

package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/CarterPerez-dev/erinyes/internal/report"
	"github.com/CarterPerez-dev/erinyes/internal/scan"
	"github.com/CarterPerez-dev/erinyes/internal/sig"
)

func sample() *report.Report {
	flagged := report.Entry{Repository: "kloxeld/xscrape", URL: "https://github.com/kloxeld/xscrape/blob/main/xscrape/fs.py"}
	flagged.FilePath = "xscrape/fs.py"
	flagged.FileSHA256 = "72d765b9be76ba841ec95548368bf9a67c9ea3823ae064d8d0beff66c4598bd9"
	flagged.FileSize = 28607
	flagged.Verdict = scan.VerdictMalicious
	flagged.TotalScore = 140
	flagged.Threshold = 60
	flagged.Signature = "pymapper-fs-loader"
	flagged.Family = "PyMapper"
	flagged.Severity = sig.SeverityCritical
	flagged.Hits = []scan.IndicatorHit{{Indicator: "xor_decoder_lambda", MatchCount: 1, Weight: 40}}

	suspicious := report.Entry{}
	suspicious.FilePath = "utils/xor.py"
	suspicious.FileSHA256 = strings.Repeat("a", 64)
	suspicious.Verdict = scan.VerdictSuspicious
	suspicious.TotalScore = 40
	suspicious.Threshold = 60
	suspicious.Signature = "pymapper-fs-loader"
	suspicious.Family = "PyMapper"
	suspicious.Severity = sig.SeverityCritical

	clean := report.Entry{}
	clean.FilePath = "xscrape/client.py"
	clean.FileSHA256 = strings.Repeat("b", 64)
	clean.Verdict = scan.VerdictClean
	clean.Signature = "pymapper-fs-loader"

	return &report.Report{
		Tool:      "erinyes",
		Version:   "0.1.0",
		Mode:      "scan",
		Target:    "./repo",
		ScannedAt: time.Date(2026, 10, 14, 20, 0, 0, 0, time.UTC),
		Rules: []report.Rule{{
			ID: "pymapper-fs-loader", Family: "PyMapper", Version: 1, Severity: "critical",
			Description: "Stage-1 Python loader.", References: []string{"Operation CLAUDEIUS"}, Threshold: 60,
		}},
		Entries: []report.Entry{flagged, suspicious, clean},
		Summary: scan.Summary{Scanned: 3, Flagged: 1, Suspicious: 1, Clean: 1, DurationMS: 12},
	}
}

func render(t *testing.T, f report.Format, opts report.Options) string {
	t.Helper()
	var buf bytes.Buffer
	if err := report.Write(&buf, f, sample(), opts); err != nil {
		t.Fatalf("Write(%s) = %v", f, err)
	}
	return buf.String()
}

func TestParseFormat(t *testing.T) {
	for in, want := range map[string]report.Format{
		"cli": report.FormatCLI, "CLI": report.FormatCLI,
		"json": report.FormatJSON, "markdown": report.FormatMarkdown,
		"md": report.FormatMarkdown, "sarif": report.FormatSARIF, " sarif ": report.FormatSARIF,
	} {
		got, err := report.ParseFormat(in)
		if err != nil {
			t.Errorf("ParseFormat(%q) = %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseFormat(%q) = %s, want %s", in, got, want)
		}
	}
	if _, err := report.ParseFormat("yaml"); err == nil {
		t.Error("ParseFormat(\"yaml\") accepted an unknown format")
	}
}

func TestCLIHidesCleanFilesByDefault(t *testing.T) {
	out := render(t, report.FormatCLI, report.Options{NoColor: true})

	if !strings.Contains(out, "xscrape/fs.py") {
		t.Error("the flagged file is missing from CLI output")
	}
	if !strings.Contains(out, "kloxeld/xscrape:xscrape/fs.py") {
		t.Error("the repository prefix is missing from the hunt-style path")
	}
	if strings.Contains(out, "client.py") {
		t.Error("a clean file appeared without -v")
	}
	if !strings.Contains(out, "Hidden: 1") {
		t.Error("the hidden-file count is missing, so the user cannot tell files were elided")
	}
	if !strings.Contains(out, "+ xor_decoder_lambda x1  (+40)") {
		t.Error("indicator evidence is missing")
	}
	if !strings.Contains(out, "Signatures: pymapper-fs-loader@1") {
		t.Error("the signature footer is missing")
	}
}

func TestCLIVerboseShowsCleanFiles(t *testing.T) {
	out := render(t, report.FormatCLI, report.Options{NoColor: true, Verbose: true})
	if !strings.Contains(out, "client.py") {
		t.Error("-v did not show the clean file")
	}
	if !strings.Contains(out, "CLEAN") {
		t.Error("-v did not print a CLEAN verdict")
	}
}

func TestCLINoColorEmitsNoEscapes(t *testing.T) {
	out := render(t, report.FormatCLI, report.Options{NoColor: true})
	if strings.Contains(out, "\x1b[") {
		t.Error("--no-color output still contains ANSI escapes")
	}
}

func TestJSONShape(t *testing.T) {
	out := render(t, report.FormatJSON, report.Options{})

	var doc struct {
		Tool             string   `json:"tool"`
		Version          string   `json:"version"`
		Mode             string   `json:"mode"`
		ScannedAt        string   `json:"scanned_at"`
		SignaturesLoaded []string `json:"signatures_loaded"`
		Results          []struct {
			File       string `json:"file"`
			SHA256     string `json:"sha256"`
			Size       int64  `json:"size"`
			Verdict    string `json:"verdict"`
			Signature  string `json:"signature"`
			TotalScore int    `json:"total_score"`
			Repository string `json:"repository"`
			Hits       []struct {
				Indicator string `json:"indicator"`
				Count     int    `json:"count"`
				Weight    int    `json:"weight"`
			} `json:"hits"`
		} `json:"results"`
		Summary struct {
			Scanned int `json:"scanned"`
			Flagged int `json:"flagged"`
			Clean   int `json:"clean"`
		} `json:"summary"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("JSON output does not parse: %v", err)
	}

	if doc.Tool != "erinyes" || doc.Version != "0.1.0" {
		t.Errorf("tool/version = %q/%q", doc.Tool, doc.Version)
	}
	if doc.ScannedAt != "2026-10-14T20:00:00Z" {
		t.Errorf("scanned_at = %q, want RFC3339 UTC", doc.ScannedAt)
	}
	if len(doc.SignaturesLoaded) != 1 || doc.SignaturesLoaded[0] != "pymapper-fs-loader@1" {
		t.Errorf("signatures_loaded = %v", doc.SignaturesLoaded)
	}
	if len(doc.Results) != 3 {
		t.Fatalf("got %d results, want all 3 including the clean one", len(doc.Results))
	}
	first := doc.Results[0]
	if first.Verdict != "malicious" || first.TotalScore != 140 {
		t.Errorf("first result verdict/score = %q/%d", first.Verdict, first.TotalScore)
	}
	if first.Repository != "kloxeld/xscrape" {
		t.Errorf("repository = %q", first.Repository)
	}
	if len(first.Hits) != 1 || first.Hits[0].Weight != 40 {
		t.Errorf("hits = %+v", first.Hits)
	}
	if doc.Summary.Scanned != 3 || doc.Summary.Flagged != 1 || doc.Summary.Clean != 1 {
		t.Errorf("summary = %+v", doc.Summary)
	}
}

func TestJSONIsAlwaysAnArrayEvenWhenEmpty(t *testing.T) {
	var buf bytes.Buffer
	empty := &report.Report{Tool: "erinyes", Version: "0.1.0", Mode: "scan", ScannedAt: time.Now()}
	if err := report.Write(&buf, report.FormatJSON, empty, report.Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"results": []`) {
		t.Errorf("empty results serialised as null, which breaks naive consumers:\n%s", buf.String())
	}
}

func TestMarkdownStructure(t *testing.T) {
	out := render(t, report.FormatMarkdown, report.Options{})

	for _, want := range []string{
		"# Erinyes scan report",
		"| Files scanned | 3 |",
		"| Flagged | 1 |",
		"## Signatures applied",
		"### `pymapper-fs-loader` (v1)",
		"Operation CLAUDEIUS",
		"## Findings",
		"| 140 | MALICIOUS | `pymapper-fs-loader` |",
		"- SHA-256: `72d765b9",
		"| `xor_decoder_lambda` | 1 | +40 |",
		"## Suspicious (below threshold, above half)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown is missing %q", want)
		}
	}
}

func TestMarkdownSaysSoWhenClean(t *testing.T) {
	rep := sample()
	rep.Entries = rep.Entries[2:]
	rep.Summary = scan.Summary{Scanned: 1, Clean: 1}

	var buf bytes.Buffer
	if err := report.Write(&buf, report.FormatMarkdown, rep, report.Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No file scored at or above") {
		t.Error("a clean markdown report does not state that nothing was found")
	}
}

func TestSARIFStructure(t *testing.T) {
	out := render(t, report.FormatSARIF, report.Options{})

	var doc struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID                   string `json:"id"`
						DefaultConfiguration struct {
							Level string `json:"level"`
						} `json:"defaultConfiguration"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("SARIF output does not parse: %v", err)
	}

	if doc.Version != "2.1.0" {
		t.Errorf("version = %q", doc.Version)
	}
	if !strings.Contains(doc.Schema, "sarif-schema-2.1.0") {
		t.Errorf("$schema = %q", doc.Schema)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("got %d runs, want 1", len(doc.Runs))
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != "erinyes" {
		t.Errorf("driver name = %q", run.Tool.Driver.Name)
	}
	if len(run.Tool.Driver.Rules) != 1 || run.Tool.Driver.Rules[0].ID != "pymapper-fs-loader" {
		t.Fatalf("rules = %+v", run.Tool.Driver.Rules)
	}
	if run.Tool.Driver.Rules[0].DefaultConfiguration.Level != "error" {
		t.Errorf("critical severity mapped to level %q, want error", run.Tool.Driver.Rules[0].DefaultConfiguration.Level)
	}
	if len(run.Results) != 2 {
		t.Fatalf("got %d results, want the malicious and suspicious entries only", len(run.Results))
	}
	if run.Results[0].Level != "error" || run.Results[1].Level != "warning" {
		t.Errorf("levels = %q, %q, want error then warning", run.Results[0].Level, run.Results[1].Level)
	}
	if run.Results[0].PartialFingerprints["erinyes/sha256"] == "" {
		t.Error("partialFingerprints is missing the sha256 fingerprint")
	}
	if run.Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI == "" {
		t.Error("result has no artifact location")
	}
}

func TestSARIFUsesTheURLForHuntResults(t *testing.T) {
	out := render(t, report.FormatSARIF, report.Options{})
	if !strings.Contains(out, "https://github.com/kloxeld/xscrape/blob/main/xscrape/fs.py") {
		t.Error("a hunt result should point at its GitHub URL")
	}
}

func TestSARIFAnchorsLocalPathsToSrcRoot(t *testing.T) {
	rep := sample()
	rep.BaseDir = "/tmp/project"
	rep.Entries = rep.Entries[:1]
	rep.Entries[0].URL = ""
	rep.Entries[0].FilePath = "/tmp/project/pkg/fs.py"

	var buf bytes.Buffer
	if err := report.Write(&buf, report.FormatSARIF, rep, report.Options{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, `"uri": "pkg/fs.py"`) {
		t.Errorf("local path was not made relative to the scan root:\n%s", out)
	}
	if !strings.Contains(out, `"uriBaseId": "SRCROOT"`) {
		t.Error("relative URIs need a uriBaseId or GitHub cannot anchor them")
	}
	if !strings.Contains(out, `"originalUriBaseIds"`) {
		t.Error("originalUriBaseIds is missing")
	}
}
