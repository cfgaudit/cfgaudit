package main

import (
	"bytes"
	"encoding/json"
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
	if fp := ccFingerprint(findings[0]); fp != issues[0].Fingerprint {
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
