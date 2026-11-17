// SPDX-License-Identifier: AGPL-3.0-only

package report_test

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/CarterPerez-dev/erinyes/internal/report"
	"github.com/CarterPerez-dev/erinyes/internal/scan"
)

func TestMarkdownFindingsAcrossVerdicts(t *testing.T) {
	for _, tc := range []struct {
		name       string
		indices    []int
		flagged    bool
		suspicious bool
	}{
		{name: "empty"},
		{name: "clean only", indices: []int{2}},
		{name: "suspicious only", indices: []int{1}, suspicious: true},
		{name: "suspicious and clean", indices: []int{1, 2}, suspicious: true},
		{name: "malicious only", indices: []int{0}, flagged: true},
		{name: "mixed", indices: []int{0, 1, 2}, flagged: true, suspicious: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := sample()
			entries := rep.Entries
			rep.Entries = nil
			rep.Summary = scan.Summary{Scanned: len(tc.indices)}
			for _, index := range tc.indices {
				e := entries[index]
				rep.Entries = append(rep.Entries, e)
				switch e.Verdict {
				case scan.VerdictMalicious:
					rep.Summary.Flagged++
				case scan.VerdictSuspicious:
					rep.Summary.Suspicious++
				case scan.VerdictClean:
					rep.Summary.Clean++
				}
			}
			var out bytes.Buffer
			if err := report.Write(&out, report.FormatMarkdown, rep, report.Options{}); err != nil {
				t.Fatal(err)
			}
			text := out.String()
			if got := strings.Contains(text, "No file scored at or above"); got == tc.flagged {
				t.Errorf("no-threshold message present=%v; malicious findings=%v", got, tc.flagged)
			}
			if got := strings.Contains(text, "| Score | Confidence | Verdict |"); got != tc.flagged {
				t.Errorf("malicious table present=%v; want=%v", got, tc.flagged)
			}
			if got := strings.Contains(text, "## Suspicious"); got != tc.suspicious {
				t.Errorf("suspicious section present=%v; want=%v", got, tc.suspicious)
			}
			if tc.suspicious {
				for _, want := range []string{"utils/xor.py", "| 40 | MEDIUM |"} {
					if strings.Count(text, want) != 1 {
						t.Errorf("expected one suspicious finding containing %q", want)
					}
				}
			}
		})
	}
}

// Fail specifically when writing the formerly omitted section, after the
// report header and no-threshold message have been written successfully.
type rejectSuspiciousSectionWriter struct{}

func (rejectSuspiciousSectionWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("## Suspicious")) {
		return 0, io.ErrClosedPipe
	}
	return len(p), nil
}

func TestMarkdownSuspiciousOnlyPropagatesLateWriteError(t *testing.T) {
	rep := sample()
	rep.Entries = rep.Entries[1:2]
	rep.Summary = scan.Summary{Scanned: 1, Suspicious: 1}
	err := report.Write(rejectSuspiciousSectionWriter{}, report.FormatMarkdown, rep, report.Options{})
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Write error=%v; want closed pipe from suspicious section", err)
	}
}
