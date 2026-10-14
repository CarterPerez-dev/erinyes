// ©AngelaMos | 2026
// json.go

package report

import (
	"encoding/json"
	"io"
	"time"

	"github.com/CarterPerez-dev/erinyes/internal/scan"
)

type jsonDocument struct {
	Tool             string       `json:"tool"`
	Version          string       `json:"version"`
	Mode             string       `json:"mode"`
	Target           string       `json:"target,omitempty"`
	ScannedAt        string       `json:"scanned_at"`
	SignaturesLoaded []string     `json:"signatures_loaded"`
	Queries          []string     `json:"queries,omitempty"`
	Results          []Entry      `json:"results"`
	Summary          scan.Summary `json:"summary"`
}

func writeJSON(w io.Writer, rep *Report) error {
	doc := jsonDocument{
		Tool:             rep.Tool,
		Version:          rep.Version,
		Mode:             rep.Mode,
		Target:           rep.Target,
		ScannedAt:        rep.ScannedAt.UTC().Format(time.RFC3339),
		SignaturesLoaded: rep.SignatureLabels(),
		Queries:          rep.Queries,
		Results:          rep.Entries,
		Summary:          rep.Summary,
	}
	if doc.Results == nil {
		doc.Results = []Entry{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
