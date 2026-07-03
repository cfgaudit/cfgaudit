package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG004_BypassPermissions(t *testing.T) {
	f := CFG004.Check(settingsTarget(t, `{"permissions":{"defaultMode":"bypassPermissions"}}`))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("expected Error severity, got %s", f[0].Severity)
	}
}

func TestCFG004_Auto(t *testing.T) {
	f := CFG004.Check(settingsTarget(t, `{"permissions":{"defaultMode":"auto"}}`))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity, got %s", f[0].Severity)
	}
}

func TestCFG004_Default_NoFinding(t *testing.T) {
	f := CFG004.Check(settingsTarget(t, `{"permissions":{"defaultMode":"default"}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding for defaultMode: default, got %d", len(f))
	}
}

func TestCFG004_Absent_NoFinding(t *testing.T) {
	f := CFG004.Check(settingsTarget(t, `{"permissions":{"allow":["Bash(make *)"]}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding when defaultMode absent, got %d", len(f))
	}
}

func TestCFG004_NoPermissions_NoFinding(t *testing.T) {
	f := CFG004.Check(settingsTarget(t, `{"env":{"FOO":"bar"}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding when permissions absent, got %d", len(f))
	}
}

func TestCFG004_NoSettings_NoFinding(t *testing.T) {
	f := CFG004.Check(&Target{})
	if len(f) != 0 {
		t.Errorf("expected no finding when settings absent, got %d", len(f))
	}
}

func TestCFG004_AcceptEdits_NoFinding(t *testing.T) {
	// "acceptEdits" is a separate mode — not flagged by this rule
	f := CFG004.Check(settingsTarget(t, `{"permissions":{"defaultMode":"acceptEdits"}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding for acceptEdits mode, got %d", len(f))
	}
}

func TestCFG004_TopLevelDefaultMode_NoFinding(t *testing.T) {
	// A top-level defaultMode is NOT the schema location (it lives under
	// permissions.defaultMode) and is ignored by Claude Code — CFG004 must not
	// fire on it (matching it would be a false positive). Regression for the bug
	// where CFG004 read only the top-level key and missed real configs (#322).
	f := CFG004.Check(settingsTarget(t, `{"defaultMode":"bypassPermissions"}`))
	if len(f) != 0 {
		t.Errorf("expected no finding for a top-level (non-schema) defaultMode, got %d: %+v", len(f), f)
	}
}
