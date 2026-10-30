// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"slices"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestEncodeCodeClimate(t *testing.T) {
	findings := []finding.Finding{
		{RuleID: "CFG001", Severity: finding.Error, File: "/proj/.claude/settings.json", Message: "bad"},
		{RuleID: "CFG024", Severity: finding.Error, File: "/proj/CLAUDE.md", Line: 3, Col: 5, Message: "hidden char"},
		{RuleID: "CFG006", Severity: finding.Warn, File: "/proj/.claude/settings.json", Message: "no deny"},
	}
	var b bytes.Buffer
	if err := encodeCodeClimate(&b, findings, "/proj"); err != nil {
		t.Fatalf("encode: %v", err)
	}
	var issues []codeClimateIssue
	if err := json.Unmarshal(b.Bytes(), &issues); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if len(issues) != 3 {
		t.Fatalf("expected 3 issues, got %d", len(issues))
	}

	// repo-relative path, severity mapping, check_name, line
	if issues[0].Location.Path != ".claude/settings.json" {
		t.Errorf("expected repo-relative path, got %q", issues[0].Location.Path)
	}
	if issues[0].Severity != "critical" {
		t.Errorf("error → critical, got %q", issues[0].Severity)
	}
	if issues[0].CheckName != "CFG001" {
		t.Errorf("check_name should be the rule ID, got %q", issues[0].CheckName)
	}
	if issues[0].Location.Lines.Begin != 1 {
		t.Errorf("missing line should default to 1, got %d", issues[0].Location.Lines.Begin)
	}
	if issues[1].Location.Lines.Begin != 3 {
		t.Errorf("expected line 3, got %d", issues[1].Location.Lines.Begin)
	}
	if issues[2].Severity != "minor" {
		t.Errorf("warn → minor, got %q", issues[2].Severity)
	}

	// fingerprints stable + unique
	if issues[0].Fingerprint == "" || len(issues[0].Fingerprint) != 64 {
		t.Errorf("expected a sha256 hex fingerprint, got %q", issues[0].Fingerprint)
	}
	if issues[0].Fingerprint == issues[2].Fingerprint {
		t.Errorf("distinct findings must have distinct fingerprints")
	}
	if fp := ccFingerprint(findings[0], ".claude/settings.json"); fp != issues[0].Fingerprint {
		t.Errorf("fingerprint not stable")
	}
}

func TestEncodeCodeClimate_Empty(t *testing.T) {
	var b bytes.Buffer
	if err := encodeCodeClimate(&b, nil, "."); err != nil {
		t.Fatal(err)
	}
	if got := bytes.TrimSpace(b.Bytes()); string(got) != "[]" {
		t.Errorf("expected empty array, got %q", got)
	}
}

func TestCCSeverity(t *testing.T) {
	for sev, want := range map[finding.Severity]string{finding.Error: "critical", finding.Warn: "minor", finding.Info: "info"} {
		if got := ccSeverity(sev); got != want {
			t.Errorf("ccSeverity(%s) = %q, want %q", sev, got, want)
		}
	}
}

// TestCCFingerprint_Golden pins the fingerprints of a fixed set of findings.
// GitLab tells new findings from existing ones by this value, so a change here
// makes every finding in every user's merge requests show up as new. Update the
// values only on purpose, and say so in the release notes (#1064).
func TestCCFingerprint_Golden(t *testing.T) {
	findings := []finding.Finding{
		{RuleID: "CFG004", Severity: finding.Error, File: "/proj/.claude/settings.json", Line: 1, Col: 17, Message: "defaultMode: \"bypassPermissions\" disables all permission checks"},
		{RuleID: "CFG024", Severity: finding.Error, File: "/proj/CLAUDE.md", Line: 3, Col: 5, Message: "hidden char"},
		{RuleID: "CFG006", Severity: finding.Warn, File: "/proj/.claude/settings.json", Message: "no deny"},
	}
	want := []string{
		"d790af47229de4926ec3d518308263c07226ea5bb6db40b7781070ce72a4ccbe", // sha256 of "CFG004|.claude/settings.json|1|<message>"
		"6a83a758610e67118ca62c67b1ef1923e6457f645d236fcd9d376358e88acbe3",
		"0ca1bd4ae7393122516505575b9478b100825c982919b07729a87709a633ba31", // no line: hashed as 0, reported as line 1
	}
	var b bytes.Buffer
	if err := encodeCodeClimate(&b, findings, "/proj"); err != nil {
		t.Fatalf("encode: %v", err)
	}
	var issues []codeClimateIssue
	if err := json.Unmarshal(b.Bytes(), &issues); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	for i, issue := range issues {
		if issue.Fingerprint != want[i] {
			t.Errorf("fingerprint of %s at %s:%d = %s, want %s", issue.CheckName, issue.Location.Path, issue.Location.Lines.Begin, issue.Fingerprint, want[i])
		}
	}
}

// TestRun_CodeClimateFingerprintIgnoresDirSpelling scans one directory spelled
// three ways; the fingerprints must not change (#1064).
func TestRun_CodeClimateFingerprintIgnoresDirSpelling(t *testing.T) {
	root := runFixture(t, map[string]string{".claude/settings.json": errorSettings})
	fingerprints := func(dir string) []string {
		t.Helper()
		_, stdout, stderr := runCLI(t, "--claude-version", "2.1.0", "--format", "codeclimate", dir)
		var issues []codeClimateIssue
		if err := json.Unmarshal([]byte(stdout), &issues); err != nil {
			t.Fatalf("%s: output not valid JSON: %v; stderr = %q", dir, err, stderr)
		}
		var fps []string
		for _, issue := range issues {
			fps = append(fps, issue.Fingerprint)
		}
		return fps
	}
	abs := fingerprints(root)
	if len(abs) == 0 {
		t.Fatal("fixture produced no findings")
	}
	t.Chdir(filepath.Dir(root))
	rel := fingerprints(filepath.Base(root))
	t.Chdir(root)
	dot := fingerprints(".")
	if !slices.Equal(abs, rel) || !slices.Equal(abs, dot) {
		t.Errorf("fingerprints differ by directory spelling:\nabsolute %v\nrelative %v\ndot      %v", abs, rel, dot)
	}
}
