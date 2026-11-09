// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG006_AllowWithoutDeny(t *testing.T) {
	f := CFG006.Check(settingsTarget(t, `{"permissions":{"allow":["Bash"]}}`))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity, got %s", f[0].Severity)
	}
}

func TestCFG006_EmptyDeny(t *testing.T) {
	f := CFG006.Check(settingsTarget(t, `{"permissions":{"allow":["Bash(*)"],"deny":[]}}`))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for empty deny, got %d", len(f))
	}
}

// A permissions block that allows nothing grants nothing a deny list could
// narrow (#1193).
func TestCFG006_PermissionsBlockWithoutAllowOrDeny(t *testing.T) {
	if f := CFG006.Check(settingsTarget(t, `{"permissions":{}}`)); len(f) != 0 {
		t.Fatalf("expected no finding when permissions block is empty, got %+v", f)
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
	tg := settingsTarget(t, `{"permissions":{"allow":["Bash"]}}`)
	tg.Scope = finding.ScopeUser
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

// #1193: a narrow allow list and a committed settings.local.json need no deny
// list; a whole-tool grant or a permissive mode does.
func TestCFG006_Issue1193(t *testing.T) {
	for _, js := range []string{
		`{"permissions":{"allow":["Bash(npm run lint:*)","Bash(npm run test:*)","WebFetch(domain:docs.example.com)"]}}`,
		`{"permissions":{"allow":["Read(./src/**)"],"defaultMode":"acceptEdits"}}`,
		`{"permissions":{"allow":["WebSearch","Grep","Glob","mcp__ide__getDiagnostics","Skill"]}}`,
		`{"permissions":{"allow":["Bash(npm run lint","Read(./docs/**)"]}}`,
	} {
		if f := CFG006.Check(settingsTarget(t, js)); len(f) != 0 {
			t.Errorf("%s: expected no finding, got %+v", js, f)
		}
	}
	local := settingsTarget(t, `{"permissions":{"allow":["Bash"]}}`)
	local.Scope = finding.ScopeProjectLocal
	if f := CFG006.Check(local); len(f) != 0 {
		t.Errorf("settings.local.json: expected no finding, got %+v", f)
	}
	for _, js := range []string{
		`{"permissions":{"allow":["Bash"]}}`,
		`{"permissions":{"allow":["Edit"]}}`,
		`{"permissions":{"allow":["Read(*)"]}}`,
		`{"permissions":{"defaultMode":"bypassPermissions"}}`,
		`{"permissions":{"defaultMode":"auto","allow":["Bash(make *)"]}}`,
		`{"permissions":{"defaultMode":"dontAsk"}}`,
	} {
		if f := CFG006.Check(settingsTarget(t, js)); len(f) != 1 || f[0].Severity != finding.Warn {
			t.Errorf("%s: expected one warn, got %+v", js, f)
		}
	}
}
