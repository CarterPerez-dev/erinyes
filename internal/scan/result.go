// ©AngelaMos | 2026
// result.go

package scan

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/CarterPerez-dev/erinyes/internal/sig"
)

type Verdict int

const (
	VerdictClean Verdict = iota
	VerdictSuspicious
	VerdictMalicious
)

func (v Verdict) String() string {
	switch v {
	case VerdictMalicious:
		return "malicious"
	case VerdictSuspicious:
		return "suspicious"
	default:
		return "clean"
	}
}

func (v Verdict) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.String())
}

func (v *Verdict) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	switch s {
	case "malicious":
		*v = VerdictMalicious
	case "suspicious":
		*v = VerdictSuspicious
	case "clean":
		*v = VerdictClean
	default:
		return fmt.Errorf("unknown verdict %q", s)
	}
	return nil
}

type IndicatorHit struct {
	Indicator  string `json:"indicator"`
	MatchCount int    `json:"count"`
	Weight     int    `json:"weight"`
}

type ScanResult struct {
	FilePath   string         `json:"file"`
	FileSHA256 string         `json:"sha256"`
	FileSize   int64          `json:"size"`
	Verdict    Verdict        `json:"verdict"`
	TotalScore int            `json:"total_score"`
	Threshold  int            `json:"threshold"`
	Hits       []IndicatorHit `json:"hits,omitempty"`
	Signature  string         `json:"signature,omitempty"`
	Family     string         `json:"family,omitempty"`
	Severity   sig.Severity   `json:"severity,omitempty"`
	KnownHash  string         `json:"known_hash_label,omitempty"`
	DurationMS int64          `json:"duration_ms"`
	Err        error          `json:"-"`
	ErrMessage string         `json:"error,omitempty"`
}

func (r *ScanResult) Flagged() bool { return r.Verdict == VerdictMalicious }

func (r *ScanResult) setErr(err error) {
	r.Err = err
	if err != nil {
		r.ErrMessage = err.Error()
	}
}

type Summary struct {
	Scanned    int   `json:"scanned"`
	Flagged    int   `json:"flagged"`
	Suspicious int   `json:"suspicious"`
	Clean      int   `json:"clean"`
	Skipped    int   `json:"skipped"`
	Errors     int   `json:"errors"`
	DurationMS int64 `json:"duration_ms"`
}

func (s *Summary) observe(r ScanResult) {
	if r.Err != nil {
		var skip *SkipError
		if errors.As(r.Err, &skip) {
			s.Skipped++
			return
		}
		s.Errors++
		return
	}
	s.Scanned++
	switch r.Verdict {
	case VerdictMalicious:
		s.Flagged++
	case VerdictSuspicious:
		s.Suspicious++
	default:
		s.Clean++
	}
}

func (s *Summary) Observe(r ScanResult) { s.observe(r) }
