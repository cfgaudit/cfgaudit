package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func projectHooksTarget(t *testing.T, scope finding.Scope) *Target {
	t.Helper()
	s, err := parser.ParseSettingsBytes([]byte(
		`{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"./setup.sh"}]}]}}`),
		".claude/settings.json")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return &Target{SettingsFile: ".claude/settings.json", Settings: s, Scope: scope}
}

func TestCFG067_ProjectScope_Warn(t *testing.T) {
	for _, scope := range []finding.Scope{finding.ScopeProject, finding.ScopeProjectLocal} {
		f := CFG067.Check(projectHooksTarget(t, scope))
		if len(f) != 1 || f[0].Severity != finding.Warn {
			t.Errorf("expected 1 Warn for scope %s, got %+v", scope, f)
		}
		if len(f) == 1 && !strings.Contains(f[0].Message, "PreToolUse") {
			t.Errorf("expected event name in message, got %q", f[0].Message)
		}
	}
}

func TestCFG067_UserScope_NoFinding(t *testing.T) {
	// Hooks in the user's own global settings are intentional — not flagged.
	if f := CFG067.Check(projectHooksTarget(t, finding.ScopeUser)); len(f) != 0 {
		t.Errorf("expected no finding at user scope, got %+v", f)
	}
}

func TestCFG067_PluginUnscopedHooks_NoFinding(t *testing.T) {
	// Plugin hooks.json targets carry no scope — not flagged here (CFG008/… still scan them).
	s, err := parser.ParseSettingsBytes([]byte(
		`{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"x"}]}]}}`), "hooks.json")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if f := CFG067.Check(&Target{SettingsFile: "hooks.json", Settings: s}); len(f) != 0 {
		t.Errorf("expected no finding for unscoped plugin hooks, got %+v", f)
	}
}

func TestCFG067_NoHooks_NoFinding(t *testing.T) {
	for _, json := range []string{
		`{"permissions":{"deny":["Read(.env)"]}}`, // no hooks
		`{"hooks":{}}`, // empty hooks block
	} {
		s, err := parser.ParseSettingsBytes([]byte(json), ".claude/settings.json")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		tg := &Target{SettingsFile: ".claude/settings.json", Settings: s, Scope: finding.ScopeProject}
		if f := CFG067.Check(tg); len(f) != 0 {
			t.Errorf("expected no finding for %s, got %+v", json, f)
		}
	}
	if f := CFG067.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding for empty target, got %+v", f)
	}
}
