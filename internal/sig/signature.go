// ©AngelaMos | 2026
// signature.go

package sig

import (
	"path/filepath"
	"strconv"
	"strings"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

func (s Severity) Valid() bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
		return true
	}
	return false
}

func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 3
	case SeverityHigh:
		return 2
	case SeverityMedium:
		return 1
	}
	return 0
}

type KnownHash struct {
	SHA256    string `yaml:"sha256" json:"sha256"`
	Label     string `yaml:"label" json:"label"`
	FirstSeen string `yaml:"first_seen" json:"first_seen,omitempty"`
}

type Retrohunt struct {
	GitHubQueries []string `yaml:"github_queries" json:"github_queries"`
	RateLimitRPS  float64  `yaml:"rate_limit_rps" json:"rate_limit_rps"`
}

type Signature struct {
	ID                  string      `yaml:"id" json:"id"`
	Version             int         `yaml:"version" json:"version"`
	Family              string      `yaml:"family" json:"family"`
	Severity            Severity    `yaml:"severity" json:"severity"`
	ConfidenceThreshold int         `yaml:"confidence_threshold" json:"confidence_threshold"`
	FilePatterns        []string    `yaml:"file_patterns" json:"file_patterns"`
	FirstSeen           string      `yaml:"first_seen" json:"first_seen,omitempty"`
	Contributor         string      `yaml:"contributor" json:"contributor,omitempty"`
	Description         string      `yaml:"description" json:"description,omitempty"`
	References          []string    `yaml:"references" json:"references,omitempty"`
	Indicators          []Indicator `yaml:"indicators" json:"indicators"`
	Retrohunt           Retrohunt   `yaml:"retrohunt" json:"retrohunt"`
	KnownHashes         []KnownHash `yaml:"known_hashes" json:"known_hashes,omitempty"`

	source    string
	hashIndex map[string]KnownHash
}

func (s *Signature) Source() string { return s.source }

func (s *Signature) Label() string {
	return s.ID + "@" + strconv.Itoa(s.Version)
}

func (s *Signature) MaxScore() int {
	total := 0
	for i := range s.Indicators {
		total += s.Indicators[i].Weight
	}
	return total
}

func (s *Signature) SuspiciousThreshold() int {
	return s.ConfidenceThreshold / 2
}

func (s *Signature) MatchesPath(path string) bool {
	base := filepath.Base(filepath.ToSlash(path))
	for _, pattern := range s.FilePatterns {
		if pattern == "*" {
			return true
		}
		if ok, err := filepath.Match(pattern, base); err == nil && ok {
			return true
		}
		if strings.Contains(pattern, "/") {
			if ok, err := filepath.Match(pattern, filepath.ToSlash(path)); err == nil && ok {
				return true
			}
		}
	}
	return false
}

func (s *Signature) MatchesKnownHash(sha256hex string) (KnownHash, bool) {
	if s.hashIndex == nil {
		return KnownHash{}, false
	}
	kh, ok := s.hashIndex[strings.ToLower(sha256hex)]
	return kh, ok
}

func (s *Signature) RateLimitRPS() float64 {
	if s.Retrohunt.RateLimitRPS <= 0 {
		return 1.0
	}
	return s.Retrohunt.RateLimitRPS
}

func (s *Signature) indexHashes() {
	s.hashIndex = make(map[string]KnownHash, len(s.KnownHashes))
	for _, kh := range s.KnownHashes {
		s.hashIndex[strings.ToLower(kh.SHA256)] = kh
	}
}
