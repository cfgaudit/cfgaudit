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

// TestVersionGating_Issue192 locks in the audit decision (#192): presence-based
// rules (CFG003/CFG004) are NOT Claude-version-gated and fire even on an ancient
// detected version, while the absence-based CFG006 IS gated and skips below its
// MinVersion. This guards against re-adding a misleading MinVersion to
// presence-based rules.
func TestVersionGating_Issue192(t *testing.T) {
	ancient := version.Version{Major: 0, Minor: 1, Patch: 0}

	// CFG003 / CFG004: presence-based → real finding, not a skip notice.
	for _, c := range []struct {
		rule Rule
		json string
		id   string
	}{
		{CFG003, `{"enableAllProjectMcpServers": true}`, "CFG003"},
		{CFG004, `{"permissions":{"defaultMode":"bypassPermissions"}}`, "CFG004"},
	} {
		withRules(t, c.rule)
		got := Run(settingsTarget(t, c.json), &ancient, nil)
		if len(got) != 1 || got[0].RuleID != c.id || got[0].Severity == finding.Info {
			t.Errorf("%s should fire on an ancient version (presence-based, not gated), got %+v", c.id, got)
		}
	}

	// CFG006: absence-based → gated; skipped (info notice) below MinVersion.
	withRules(t, CFG006)
	got := Run(settingsTarget(t, `{"permissions":{"allow":["Bash(make *)"]}}`), &ancient, nil)
	if len(got) != 1 || got[0].Severity != finding.Info {
		t.Errorf("CFG006 should be version-gated (info skip) on an ancient version, got %+v", got)
	}
	// ...and fires normally once the version is recent enough.
	recent := version.Version{Major: 2, Minor: 1, Patch: 150}
	got = Run(settingsTarget(t, `{"permissions":{"allow":["Bash(make *)"]}}`), &recent, nil)
	if len(got) != 1 || got[0].RuleID != "CFG006" || got[0].Severity != finding.Warn {
		t.Errorf("CFG006 should fire normally on a recent version, got %+v", got)
	}
}

// plainRule implements Rule but not Versioned.
type plainRule struct{ id string }

func (p *plainRule) ID() string { return p.id }
func (p *plainRule) Check(t *Target) []finding.Finding {
	return []finding.Finding{{RuleID: p.id, Severity: finding.Warn, File: t.SettingsFile}}
}
