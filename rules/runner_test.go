package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/version"
)

// stubRule is a minimal Rule for testing the runner without touching real rules.
type stubRule struct {
	id      string
	minVer  string
	results []finding.Finding
}

func (s *stubRule) ID() string                        { return s.id }
func (s *stubRule) MinVersion() string                { return s.minVer }
func (s *stubRule) Check(_ *Target) []finding.Finding { return s.results }

func withRules(t *testing.T, rs ...Rule) {
	t.Helper()
	saved := All
	All = rs
	t.Cleanup(func() { All = saved })
}

func TestRun_NilVersion_RunsAllRules(t *testing.T) {
	stub := &stubRule{id: "TST001", minVer: "9.9.9", results: []finding.Finding{{RuleID: "TST001", Severity: finding.Warn}}}
	withRules(t, stub)

	got := Run(&Target{SettingsFile: "x"}, nil, nil)
	if len(got) != 1 || got[0].Severity != finding.Warn {
		t.Fatalf("expected 1 warn finding when version is nil, got %+v", got)
	}
}

func TestRun_DetectedBelowMin_EmitsSkipNotice(t *testing.T) {
	stub := &stubRule{id: "TST002", minVer: "2.1.91", results: []finding.Finding{{RuleID: "TST002", Severity: finding.Error}}}
	withRules(t, stub)

	detected := version.Version{Major: 2, Minor: 1, Patch: 50}
	got := Run(&Target{SettingsFile: "x"}, &detected, nil)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding (the skip notice), got %d", len(got))
	}
	if got[0].Severity != finding.Info {
		t.Errorf("expected Info severity, got %s", got[0].Severity)
	}
	if !strings.Contains(got[0].Message, "2.1.91") || !strings.Contains(got[0].Message, "2.1.50") {
		t.Errorf("expected skip message to mention both versions, got: %s", got[0].Message)
	}
}

func TestRun_DetectedAtOrAboveMin_RunsRule(t *testing.T) {
	stub := &stubRule{id: "TST003", minVer: "2.1.91", results: []finding.Finding{{RuleID: "TST003", Severity: finding.Error}}}
	withRules(t, stub)

	detected := version.Version{Major: 2, Minor: 1, Patch: 91}
	got := Run(&Target{SettingsFile: "x"}, &detected, nil)
	if len(got) != 1 || got[0].Severity != finding.Error {
		t.Fatalf("expected rule to run at exact min version, got %+v", got)
	}
}

func TestRun_EmptyMinVersion_RunsRule(t *testing.T) {
	stub := &stubRule{id: "TST004", minVer: "", results: []finding.Finding{{RuleID: "TST004", Severity: finding.Warn}}}
	withRules(t, stub)

	detected := version.Version{Major: 0, Minor: 0, Patch: 1}
	got := Run(&Target{SettingsFile: "x"}, &detected, nil)
	if len(got) != 1 || got[0].Severity != finding.Warn {
		t.Fatalf("expected empty MinVersion to disable gating, got %+v", got)
	}
}

func TestRun_NonVersionedRule_AlwaysRuns(t *testing.T) {
	plain := &plainRule{id: "TST005"}
	withRules(t, plain)

	detected := version.Version{Major: 0, Minor: 0, Patch: 1}
	got := Run(&Target{SettingsFile: "x"}, &detected, nil)
	if len(got) != 1 {
		t.Fatalf("expected non-Versioned rule to run, got %d findings", len(got))
	}
}

// plainRule implements Rule but not Versioned.
type plainRule struct{ id string }

func (p *plainRule) ID() string { return p.id }
func (p *plainRule) Check(t *Target) []finding.Finding {
	return []finding.Finding{{RuleID: p.id, Severity: finding.Warn, File: t.SettingsFile}}
}
