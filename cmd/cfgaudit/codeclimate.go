package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// Code Climate / GitLab Code Quality report. GitLab consumes this format (not
// SARIF) for inline merge-request findings via `artifacts:reports:codequality`.
// See https://docs.gitlab.com/ee/ci/testing/code_quality.html

type codeClimateIssue struct {
	Description string     `json:"description"`
	CheckName   string     `json:"check_name"`
	Fingerprint string     `json:"fingerprint"`
	Severity    string     `json:"severity"`
	Location    ccLocation `json:"location"`
}

type ccLocation struct {
	Path  string  `json:"path"`
	Lines ccLines `json:"lines"`
}

type ccLines struct {
	Begin int `json:"begin"`
}

// encodeCodeClimate writes findings as a Code Climate JSON array. dir is the scan
// root, used to make paths repo-relative.
func encodeCodeClimate(w io.Writer, findings []finding.Finding, dir string) error {
	issues := make([]codeClimateIssue, 0, len(findings))
	for _, f := range findings {
		begin := f.Line
		if begin <= 0 {
			begin = 1
		}
		issues = append(issues, codeClimateIssue{
			Description: f.RuleID + ": " + f.Message,
			CheckName:   f.RuleID,
			Fingerprint: ccFingerprint(f),
			Severity:    ccSeverity(f.Severity),
			Location:    ccLocation{Path: ccRelPath(dir, f.File), Lines: ccLines{Begin: begin}},
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(issues)
}

// ccSeverity maps a cfgaudit severity to a GitLab Code Quality severity.
func ccSeverity(s finding.Severity) string {
	switch s {
	case finding.Error:
		return "critical"
	case finding.Warn:
		return "minor"
	default:
		return "info"
	}
}

// ccFingerprint is a stable, unique-per-finding hash so GitLab can track findings
// across pipelines.
func ccFingerprint(f finding.Finding) string {
	key := strings.Join([]string{f.RuleID, f.File, strconv.Itoa(f.Line), f.Message}, "|")
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func ccRelPath(dir, file string) string {
	if file == "" {
		return ""
	}
	if rel, err := filepath.Rel(dir, file); err == nil {
		file = rel
	}
	return filepath.ToSlash(file)
}
