package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG004_BypassPermissions(t *testing.T) {
	f := CFG004.Check(settingsTarget(t, `{"defaultMode":"bypassPermissions"}`))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("expected Error severity, got %s", f[0].Severity)
	}
}

func TestCFG004_Auto(t *testing.T) {
	f := CFG004.Check(settingsTarget(t, `{"defaultMode":"auto"}`))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity, got %s", f[0].Severity)
	}
}

func TestCFG004_Default_NoFinding(t *testing.T) {
	f := CFG004.Check(settingsTarget(t, `{"defaultMode":"default"}`))
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

func TestCFG004_NoSettings_NoFinding(t *testing.T) {
	f := CFG004.Check(&Target{})
	if len(f) != 0 {
		t.Errorf("expected no finding when settings absent, got %d", len(f))
	}
}

func TestCFG004_AcceptEdits_NoFinding(t *testing.T) {
	// "acceptEdits" is a separate mode — not flagged by this rule
	f := CFG004.Check(settingsTarget(t, `{"defaultMode":"acceptEdits"}`))
	if len(f) != 0 {
		t.Errorf("expected no finding for acceptEdits mode, got %d", len(f))
	}
}
