// ©AngelaMos | 2026
// scorer.go

package scan

import "github.com/CarterPerez-dev/erinyes/internal/sig"

func Score(hits []IndicatorHit) int {
	total := 0
	for _, h := range hits {
		total += h.Weight
	}
	return total
}

func Classify(score int, s *sig.Signature) Verdict {
	switch {
	case score >= s.ConfidenceThreshold:
		return VerdictMalicious
	case score >= s.SuspiciousThreshold():
		return VerdictSuspicious
	default:
		return VerdictClean
	}
}

func Rate(v Verdict, score int, knownHash bool) Confidence {
	switch {
	case knownHash || v == VerdictMalicious:
		return ConfidenceHigh
	case v == VerdictSuspicious:
		return ConfidenceMedium
	case score > 0:
		return ConfidenceLow
	default:
		return ConfidenceNone
	}
}

func Better(a, b ScanResult) bool {
	if a.Verdict != b.Verdict {
		return a.Verdict > b.Verdict
	}
	if (a.KnownHash != "") != (b.KnownHash != "") {
		return a.KnownHash != ""
	}
	if a.Verdict == VerdictMalicious && a.Severity.Rank() != b.Severity.Rank() {
		return a.Severity.Rank() > b.Severity.Rank()
	}
	if a.TotalScore != b.TotalScore {
		return a.TotalScore > b.TotalScore
	}
	return a.Severity.Rank() > b.Severity.Rank()
}
