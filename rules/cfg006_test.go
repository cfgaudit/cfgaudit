package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG006_AllowWithoutDeny(t *testing.T) {
	f := CFG006.Check(settingsTarget(t, `{"permissions":{"allow":["Bash(make *)"]}}`))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity, got %s", f[0].Severity)
	}
}

func TestCFG006_EmptyDeny(t *testing.T) {
	f := CFG006.Check(settingsTarget(t, `{"permissions":{"allow":["Bash(make *)"],"deny":[]}}`))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for empty deny, got %d", len(f))
	}
}

func TestCFG006_PermissionsBlockWithoutAllowOrDeny(t *testing.T) {
	f := CFG006.Check(settingsTarget(t, `{"permissions":{}}`))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding when permissions block is empty, got %d", len(f))
	}
}

func TestCFG006_NonEmptyDeny_NoFinding(t *testing.T) {
	f := CFG006.Check(settingsTarget(t, `{"permissions":{"allow":["Bash(make *)"],"deny":["Bash(rm -rf *)"]}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding when deny is populated, got %d", len(f))
	}
}

// settings.local.json with no deny of its own is fine when the sibling
// settings.json already defines one — Claude Code merges them (issue #180).
func TestCFG006_SiblingDeny_Suppressed(t *testing.T) {
	tg := settingsTarget(t, `{"permissions":{"allow":["Bash(fhirlint validate *)"]}}`)
	tg.Scope = finding.ScopeProjectLocal
	tg.SiblingDeny = true
	if f := CFG006.Check(tg); len(f) != 0 {
		t.Errorf("expected no finding when a sibling settings.json has deny, got %+v", f)
	}
	tg.SiblingDeny = false
	if f := CFG006.Check(tg); len(f) != 1 {
		t.Errorf("expected a finding when no sibling deny exists, got %+v", f)
	}
}

func TestCFG006_NoPermissions_NoFinding(t *testing.T) {
	f := CFG006.Check(settingsTarget(t, `{"env":{"FOO":"bar"}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding when permissions block absent, got %d", len(f))
	}
}

func TestCFG006_NoSettings_NoFinding(t *testing.T) {
	f := CFG006.Check(&Target{})
	if len(f) != 0 {
		t.Errorf("expected no finding when settings absent, got %d", len(f))
	}
}
