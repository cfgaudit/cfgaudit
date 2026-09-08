package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/version"
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

// scopedSettingsTarget builds a settings target with an explicit scope and a
// detected Claude Code version, the two inputs that decide whether the value is
// still honoured from the file being audited.
func scopedSettingsTarget(t *testing.T, json string, scope finding.Scope, ver string) *Target {
	t.Helper()
	tgt := settingsTarget(t, json)
	tgt.Scope = scope
	if ver != "" {
		v, err := version.Parse(ver)
		if err != nil {
			t.Fatalf("parse version %q: %v", ver, err)
		}
		tgt.ClaudeVersion = &v
	}
	return tgt
}

const bypassJSON = `{"permissions":{"defaultMode":"bypassPermissions"}}`
const autoJSON = `{"permissions":{"defaultMode":"auto"}}`

func TestCFG004_BypassInertInRepoScopes(t *testing.T) {
	for _, scope := range []finding.Scope{finding.ScopeProject, finding.ScopeProjectLocal} {
		f := CFG004.Check(scopedSettingsTarget(t, bypassJSON, scope, "2.1.257"))
		if len(f) != 1 {
			t.Fatalf("%s: expected 1 finding, got %d", scope, len(f))
		}
		if f[0].Severity != finding.Warn {
			t.Errorf("%s: expected Warn once the value is ignored, got %s", scope, f[0].Severity)
		}
		if !strings.Contains(f[0].Message, "2.1.257") {
			t.Errorf("%s: message should name the detected version, got: %s", scope, f[0].Message)
		}
		if !strings.Contains(f[0].Message, "older release") {
			t.Errorf("%s: message should keep the older-release exposure, got: %s", scope, f[0].Message)
		}
	}
}

// One patch below the cutoff the value is still honoured, so the finding must
// keep its full weight.
func TestCFG004_BypassStillHonouredBelowCutoff(t *testing.T) {
	f := CFG004.Check(scopedSettingsTarget(t, bypassJSON, finding.ScopeProject, "2.1.256"))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error below the cutoff, got %+v", f)
	}
}

// No detected version is not evidence that the newest behaviour applies: the
// audited file is read by installations cfgaudit knows nothing about.
func TestCFG004_BypassUndetectedVersionKeepsError(t *testing.T) {
	f := CFG004.Check(scopedSettingsTarget(t, bypassJSON, finding.ScopeProject, ""))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error with no detected version, got %+v", f)
	}
}

// User settings are not repo-controllable, so nothing changes there.
func TestCFG004_BypassUserScopeUnchanged(t *testing.T) {
	f := CFG004.Check(scopedSettingsTarget(t, bypassJSON, finding.ScopeUser, "2.1.263"))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error in user scope, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "user-global scope") {
		t.Errorf("expected the user-scope note, got: %s", f[0].Message)
	}
}

func TestCFG004_AutoInertInRepoScopes(t *testing.T) {
	f := CFG004.Check(scopedSettingsTarget(t, autoJSON, finding.ScopeProject, "2.1.252"))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Info {
		t.Errorf("expected Info once the value is ignored, got %s", f[0].Severity)
	}
	if !strings.Contains(f[0].Message, "2.1.252") {
		t.Errorf("message should name the detected version, got: %s", f[0].Message)
	}
}

func TestCFG004_AutoBelowCutoffAndUserScopeStayWarn(t *testing.T) {
	below := CFG004.Check(scopedSettingsTarget(t, autoJSON, finding.ScopeProject, "2.1.251"))
	if len(below) != 1 || below[0].Severity != finding.Warn {
		t.Fatalf("expected 1 Warn below the auto cutoff, got %+v", below)
	}
	user := CFG004.Check(scopedSettingsTarget(t, autoJSON, finding.ScopeUser, "2.1.263"))
	if len(user) != 1 || user[0].Severity != finding.Warn {
		t.Fatalf("expected 1 Warn in user scope, got %+v", user)
	}
}
