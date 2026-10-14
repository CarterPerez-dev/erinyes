// ©AngelaMos | 2026
// report.go

package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/CarterPerez-dev/erinyes/internal/scan"
)

type Format string

const (
	FormatCLI      Format = "cli"
	FormatJSON     Format = "json"
	FormatMarkdown Format = "markdown"
	FormatSARIF    Format = "sarif"
)

func ParseFormat(s string) (Format, error) {
	switch Format(strings.ToLower(strings.TrimSpace(s))) {
	case FormatCLI:
		return FormatCLI, nil
	case FormatJSON:
		return FormatJSON, nil
	case FormatMarkdown, "md":
		return FormatMarkdown, nil
	case FormatSARIF:
		return FormatSARIF, nil
	}
	return "", fmt.Errorf("unknown format %q (want cli, json, markdown or sarif)", s)
}

type Entry struct {
	scan.ScanResult
	Repository string `json:"repository,omitempty"`
	URL        string `json:"url,omitempty"`
	Origin     string `json:"origin,omitempty"`
}

type Rule struct {
	ID          string
	Family      string
	Version     int
	Severity    string
	Description string
	References  []string
	Threshold   int
}

type Report struct {
	Tool      string
	Version   string
	Mode      string
	Target    string
	BaseDir   string
	ScannedAt time.Time
	Rules     []Rule
	Entries   []Entry
	Summary   scan.Summary
	Queries   []string
}

func (r *Report) SignatureLabels() []string {
	out := make([]string, 0, len(r.Rules))
	for _, rule := range r.Rules {
		out = append(out, fmt.Sprintf("%s@%d", rule.ID, rule.Version))
	}
	return out
}

func (r *Report) Flagged() []Entry {
	var out []Entry
	for _, e := range r.Entries {
		if e.Verdict == scan.VerdictMalicious {
			out = append(out, e)
		}
	}
	return out
}

type Options struct {
	Verbose bool
	NoColor bool
}

func Write(w io.Writer, f Format, rep *Report, opts Options) error {
	switch f {
	case FormatJSON:
		return writeJSON(w, rep)
	case FormatMarkdown:
		return writeMarkdown(w, rep)
	case FormatSARIF:
		return writeSARIF(w, rep)
	default:
		return writeCLI(w, rep, opts)
	}
}
