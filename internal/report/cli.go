// ©AngelaMos | 2026
// cli.go

package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"

	"github.com/CarterPerez-dev/erinyes/internal/scan"
)

var (
	colMalicious  = color.New(color.FgRed, color.Bold)
	colSuspicious = color.New(color.FgYellow)
	colClean      = color.New(color.FgGreen)
	colIndicator  = color.New(color.FgCyan)
	colDim        = color.New(color.Faint)
	colErr        = color.New(color.FgMagenta)
)

func verdictLabel(e Entry) string {
	switch e.Verdict {
	case scan.VerdictMalicious:
		switch {
		case e.KnownHash != "" && e.Family != "":
			return "MALICIOUS (" + e.Family + ", known)"
		case e.KnownHash != "":
			return "MALICIOUS (known hash)"
		case e.Family != "":
			return "MALICIOUS (" + e.Family + ")"
		}
		return "MALICIOUS"
	case scan.VerdictSuspicious:
		return "SUSPICIOUS"
	default:
		return "CLEAN"
	}
}

func verdictColor(v scan.Verdict) *color.Color {
	switch v {
	case scan.VerdictMalicious:
		return colMalicious
	case scan.VerdictSuspicious:
		return colSuspicious
	default:
		return colClean
	}
}

type cliWriter struct {
	w     io.Writer
	color bool
	err   error
}

func (c *cliWriter) plain(format string, args ...any) {
	if c.err != nil {
		return
	}
	_, c.err = fmt.Fprintf(c.w, format, args...)
}

func (c *cliWriter) tinted(col *color.Color, s string) {
	if c.err != nil {
		return
	}
	if !c.color {
		_, c.err = fmt.Fprint(c.w, s)
		return
	}
	_, c.err = col.Fprint(c.w, s)
}

func writeCLI(w io.Writer, rep *Report, opts Options) error {
	cw := &cliWriter{w: w, color: !opts.NoColor}

	visible := make([]Entry, 0, len(rep.Entries))
	hidden := 0
	for _, e := range rep.Entries {
		switch {
		case e.Err != nil && !opts.Verbose:
			hidden++
		case e.Verdict == scan.VerdictClean && e.Err == nil && !opts.Verbose:
			hidden++
		default:
			visible = append(visible, e)
		}
	}

	if len(visible) > 0 {
		cw.plain("%5s  %-28s  %s\n", "SCORE", "VERDICT", "FILE")
		cw.plain("%s\n", strings.Repeat("-", 78))
	}

	for _, e := range visible {
		if e.Err != nil {
			cw.tinted(colErr, fmt.Sprintf("%5s  %-28s  ", "-", "ERROR"))
			cw.plain("%s\n", displayPath(e))
			cw.plain("         %s\n", e.ErrMessage)
			continue
		}

		cw.tinted(verdictColor(e.Verdict), fmt.Sprintf("%5d  %-28s  ", e.TotalScore, verdictLabel(e)))
		cw.plain("%s\n", displayPath(e))

		if e.KnownHash != "" {
			cw.plain("         + known hash  %s\n", e.KnownHash)
		}
		for _, h := range e.Hits {
			cw.plain("         + ")
			cw.tinted(colIndicator, h.Indicator)
			cw.plain(" x%d  (+%d)\n", h.MatchCount, h.Weight)
		}
		if e.URL != "" {
			cw.plain("           ")
			cw.tinted(colDim, e.URL+"\n")
		}
	}

	if len(visible) > 0 {
		cw.plain("\n")
	}

	s := rep.Summary
	cw.plain("Scanned: %d files\n", s.Scanned)
	cw.plain("Flagged: %d\n", s.Flagged)
	if s.Suspicious > 0 {
		cw.plain("Suspicious: %d\n", s.Suspicious)
	}
	if hidden > 0 {
		cw.plain("Hidden: %d (clean or errored, use -v to show)\n", hidden)
	}
	if s.Skipped > 0 {
		cw.plain("Skipped: %d (no matching file_patterns or over size limit)\n", s.Skipped)
	}
	if s.Errors > 0 {
		cw.plain("Errors: %d\n", s.Errors)
	}
	cw.plain("Signatures: %s\n", strings.Join(rep.SignatureLabels(), ", "))
	cw.plain("Elapsed: %dms\n", s.DurationMS)

	return cw.err
}

func displayPath(e Entry) string {
	if e.Repository != "" && !strings.Contains(e.FilePath, ":") {
		return e.Repository + ":" + e.FilePath
	}
	return e.FilePath
}
