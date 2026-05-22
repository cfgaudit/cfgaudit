package main

import (
	"encoding/json"
	"io"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/rules"
)

// SARIF 2.1.0 output. See https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
// We emit the minimum that GitHub Code Scanning accepts: a single run, a
// tool.driver listing every registered rule, and one result per finding.

type sarifDoc struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID      string `json:"id"`
	HelpURI string `json:"helpUri,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
}

func encodeSARIF(w io.Writer, findings []finding.Finding, driverVersion string, allRules []rules.Rule) error {
	doc := sarifDoc{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "cfgaudit",
						Version:        driverVersion,
						InformationURI: "https://github.com/cfgaudit/cfgaudit",
						Rules:          sarifRules(allRules),
					},
				},
				Results: sarifResults(findings),
			},
		},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func sarifRules(rs []rules.Rule) []sarifRule {
	out := make([]sarifRule, 0, len(rs))
	for _, r := range rs {
		id := r.ID()
		out = append(out, sarifRule{
			ID:      id,
			HelpURI: "https://github.com/cfgaudit/cfgaudit/blob/main/docs/rules/" + id + ".md",
		})
	}
	return out
}

func sarifResults(findings []finding.Finding) []sarifResult {
	out := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		loc := sarifLocation{
			PhysicalLocation: sarifPhysical{
				ArtifactLocation: sarifArtifact{URI: f.File},
			},
		}
		if f.Line > 0 {
			loc.PhysicalLocation.Region = &sarifRegion{
				StartLine:   f.Line,
				StartColumn: f.Col,
			}
		}
		out = append(out, sarifResult{
			RuleID:    f.RuleID,
			Level:     sarifLevel(f.Severity),
			Message:   sarifMessage{Text: f.Message},
			Locations: []sarifLocation{loc},
		})
	}
	return out
}

func sarifLevel(s finding.Severity) string {
	switch s {
	case finding.Error:
		return "error"
	case finding.Warn:
		return "warning"
	case finding.Info:
		return "note"
	default:
		return "none"
	}
}
