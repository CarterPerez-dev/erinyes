// ©AngelaMos | 2026
// sarif.go

package report

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/CarterPerez-dev/erinyes/internal/scan"
)

const (
	sarifVersion = "2.1.0"
	sarifSchema  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	toolURI      = "https://github.com/CarterPerez-dev/erinyes"
	srcRoot      = "SRCROOT"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool               sarifTool               `json:"tool"`
	OriginalURIBaseIDs map[string]sarifURIBase `json:"originalUriBaseIds,omitempty"`
	Results            []sarifResult           `json:"results"`
	Invocati           []sarifInvoc            `json:"invocations,omitempty"`
}

type sarifURIBase struct {
	URI string `json:"uri"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	InformationURI  string      `json:"informationUri"`
	Version         string      `json:"version"`
	SemanticVersion string      `json:"semanticVersion,omitempty"`
	Rules           []sarifRule `json:"rules"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifRule struct {
	ID                   string          `json:"id"`
	Name                 string          `json:"name"`
	ShortDescription     sarifText       `json:"shortDescription"`
	FullDescription      sarifText       `json:"fullDescription"`
	Help                 sarifText       `json:"help"`
	HelpURI              string          `json:"helpUri,omitempty"`
	DefaultConfiguration sarifRuleConfig `json:"defaultConfiguration"`
	Properties           sarifRuleProps  `json:"properties"`
}

type sarifRuleProps struct {
	Tags      []string `json:"tags"`
	Family    string   `json:"family"`
	Severity  string   `json:"severity"`
	Threshold int      `json:"confidenceThreshold"`
	Precision string   `json:"precision"`
}

type sarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          sarifResultProps  `json:"properties"`
}

type sarifResultProps struct {
	Score     int               `json:"score"`
	Threshold int               `json:"threshold"`
	Verdict   string            `json:"verdict"`
	Family    string            `json:"family"`
	SizeBytes int64             `json:"sizeBytes"`
	KnownHash string            `json:"knownHash,omitempty"`
	URL       string            `json:"url,omitempty"`
	Hits      map[string]int    `json:"indicatorMatches,omitempty"`
	Weights   map[string]int    `json:"indicatorWeights,omitempty"`
	Extra     map[string]string `json:"-"`
}

type sarifInvoc struct {
	ExecutionSuccessful bool   `json:"executionSuccessful"`
	CommandLine         string `json:"commandLine,omitempty"`
}

func sarifLevel(severity string, v scan.Verdict) string {
	if v == scan.VerdictSuspicious {
		return "warning"
	}
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func writeSARIF(w io.Writer, rep *Report) error {
	rules := make([]sarifRule, 0, len(rep.Rules))
	index := make(map[string]int, len(rep.Rules))

	for i, r := range rep.Rules {
		index[r.ID] = i
		desc := strings.TrimSpace(r.Description)
		if desc == "" {
			desc = fmt.Sprintf("Obfuscated-malware signature for the %s family.", r.Family)
		}
		help := desc
		if len(r.References) > 0 {
			help += "\n\nReferences:\n- " + strings.Join(r.References, "\n- ")
		}
		rules = append(rules, sarifRule{
			ID:               r.ID,
			Name:             r.ID,
			ShortDescription: sarifText{Text: fmt.Sprintf("%s: %s stage-1 obfuscated loader", r.ID, r.Family)},
			FullDescription:  sarifText{Text: desc},
			Help:             sarifText{Text: help},
			HelpURI:          toolURI,
			DefaultConfiguration: sarifRuleConfig{
				Level: sarifLevel(r.Severity, scan.VerdictMalicious),
			},
			Properties: sarifRuleProps{
				Tags:      []string{"security", "malware", "obfuscation", strings.ToLower(r.Family)},
				Family:    r.Family,
				Severity:  r.Severity,
				Threshold: r.Threshold,
				Precision: "high",
			},
		})
	}

	results := make([]sarifResult, 0, len(rep.Entries))
	for _, e := range rep.Entries {
		if e.Verdict == scan.VerdictClean || e.Err != nil {
			continue
		}
		ri, ok := index[e.Signature]
		if !ok {
			ri = 0
		}
		severity := string(e.Severity)
		msg := fmt.Sprintf("%s matched %s with score %d (threshold %d).", displayPath(e), e.Signature, e.TotalScore, e.Threshold)
		if e.KnownHash != "" {
			msg = fmt.Sprintf("%s is a known %s sample: %s.", displayPath(e), e.Family, e.KnownHash)
		}

		hits := make(map[string]int, len(e.Hits))
		weights := make(map[string]int, len(e.Hits))
		for _, h := range e.Hits {
			hits[h.Indicator] = h.MatchCount
			weights[h.Indicator] = h.Weight
		}

		results = append(results, sarifResult{
			RuleID:    e.Signature,
			RuleIndex: ri,
			Level:     sarifLevel(severity, e.Verdict),
			Message:   sarifText{Text: msg},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: artifactLocation(e, rep.BaseDir),
					Region:           sarifRegion{StartLine: 1},
				},
			}},
			PartialFingerprints: map[string]string{
				"erinyes/sha256": e.FileSHA256,
			},
			Properties: sarifResultProps{
				Score:     e.TotalScore,
				Threshold: e.Threshold,
				Verdict:   e.Verdict.String(),
				Family:    e.Family,
				SizeBytes: e.FileSize,
				KnownHash: e.KnownHash,
				URL:       e.URL,
				Hits:      hits,
				Weights:   weights,
			},
		})
	}

	var bases map[string]sarifURIBase
	if abs, err := filepath.Abs(rep.BaseDir); err == nil && rep.BaseDir != "" {
		bases = map[string]sarifURIBase{
			srcRoot: {URI: "file://" + filepath.ToSlash(abs) + "/"},
		}
	}

	doc := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			OriginalURIBaseIDs: bases,
			Tool: sarifTool{Driver: sarifDriver{
				Name:            rep.Tool,
				InformationURI:  toolURI,
				Version:         rep.Version,
				SemanticVersion: rep.Version,
				Rules:           rules,
			}},
			Results: results,
			Invocati: []sarifInvoc{{
				ExecutionSuccessful: rep.Summary.Errors == 0,
			}},
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func artifactLocation(e Entry, baseDir string) sarifArtifactLocation {
	if e.URL != "" {
		return sarifArtifactLocation{URI: e.URL}
	}
	p := filepath.ToSlash(strings.TrimPrefix(e.FilePath, "./"))
	if baseDir == "" {
		return sarifArtifactLocation{URI: p}
	}
	rel, err := filepath.Rel(baseDir, e.FilePath)
	if err != nil || strings.HasPrefix(rel, "..") {
		return sarifArtifactLocation{URI: p}
	}
	return sarifArtifactLocation{URI: filepath.ToSlash(rel), URIBaseID: srcRoot}
}
