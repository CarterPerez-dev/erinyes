// ©AngelaMos | 2026
// markdown.go

package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/CarterPerez-dev/erinyes/internal/scan"
)

type mdWriter struct {
	w   io.Writer
	err error
}

func (m *mdWriter) line(format string, args ...any) {
	if m.err != nil {
		return
	}
	_, m.err = fmt.Fprintf(m.w, format, args...)
}

func writeMarkdown(w io.Writer, rep *Report) error {
	md := &mdWriter{w: w}

	md.line("# Erinyes %s report\n\n", rep.Mode)
	md.line("| Field | Value |\n|---|---|\n")
	md.line("| Tool | erinyes %s |\n", rep.Version)
	md.line("| Mode | %s |\n", rep.Mode)
	if rep.Target != "" {
		md.line("| Target | `%s` |\n", rep.Target)
	}
	md.line("| Scanned at | %s |\n", rep.ScannedAt.UTC().Format(time.RFC3339))
	md.line("| Signatures | %s |\n", strings.Join(rep.SignatureLabels(), ", "))
	md.line("| Files scanned | %d |\n", rep.Summary.Scanned)
	md.line("| Flagged | %d |\n", rep.Summary.Flagged)
	md.line("| Suspicious | %d |\n", rep.Summary.Suspicious)
	md.line("| Clean | %d |\n", rep.Summary.Clean)
	if rep.Summary.Skipped > 0 {
		md.line("| Skipped | %d |\n", rep.Summary.Skipped)
	}
	if rep.Summary.Errors > 0 {
		md.line("| Errors | %d |\n", rep.Summary.Errors)
	}
	md.line("| Elapsed | %dms |\n\n", rep.Summary.DurationMS)

	if len(rep.Queries) > 0 {
		md.line("## Retrohunt queries\n\n")
		for _, q := range rep.Queries {
			md.line("- `%s`\n", q)
		}
		md.line("\n")
	}

	md.line("## Signatures applied\n\n")
	for _, r := range rep.Rules {
		md.line("### `%s` (v%d)\n\n", r.ID, r.Version)
		md.line("- Family: **%s**\n", r.Family)
		md.line("- Severity: **%s**\n", r.Severity)
		md.line("- Confidence threshold: %d\n", r.Threshold)
		if r.Description != "" {
			md.line("\n%s\n", strings.TrimSpace(r.Description))
		}
		if len(r.References) > 0 {
			md.line("\nReferences:\n")
			for _, ref := range r.References {
				md.line("- %s\n", ref)
			}
		}
		md.line("\n")
	}

	md.line("## Findings\n\n")

	flagged := rep.Flagged()
	if len(flagged) == 0 {
		md.line("No file scored at or above its signature's confidence threshold.\n")
		return md.err
	}

	md.line("| Score | Verdict | Signature | File |\n|---:|---|---|---|\n")
	for _, e := range flagged {
		md.line("| %d | %s | `%s` | `%s` |\n", e.TotalScore, strings.ToUpper(e.Verdict.String()), e.Signature, displayPath(e))
	}
	md.line("\n")

	for _, e := range flagged {
		md.line("### `%s`\n\n", displayPath(e))
		md.line("- SHA-256: `%s`\n", e.FileSHA256)
		md.line("- Size: %d bytes\n", e.FileSize)
		md.line("- Signature: `%s` (threshold %d)\n", e.Signature, e.Threshold)
		md.line("- Score: **%d**\n", e.TotalScore)
		if e.KnownHash != "" {
			md.line("- Known sample: %s\n", e.KnownHash)
		}
		if e.URL != "" {
			md.line("- Source: %s\n", e.URL)
		}
		if e.Origin != "" {
			md.line("- Retrieved via: %s\n", e.Origin)
		}
		if len(e.Hits) > 0 {
			md.line("\n| Indicator | Matches | Weight |\n|---|---:|---:|\n")
			for _, h := range e.Hits {
				md.line("| `%s` | %d | +%d |\n", h.Indicator, h.MatchCount, h.Weight)
			}
		}
		md.line("\n")
	}

	var suspicious []Entry
	for _, e := range rep.Entries {
		if e.Verdict == scan.VerdictSuspicious {
			suspicious = append(suspicious, e)
		}
	}
	if len(suspicious) > 0 {
		md.line("## Suspicious (below threshold, above half)\n\n")
		md.line("| Score | Signature | File |\n|---:|---|---|\n")
		for _, e := range suspicious {
			md.line("| %d | `%s` | `%s` |\n", e.TotalScore, e.Signature, displayPath(e))
		}
		md.line("\n")
	}

	return md.err
}
