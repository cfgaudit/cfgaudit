// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/version"
)

func TestCFG002_UnrestrictedEdit(t *testing.T) {
	f := CFG002.Check(settingsTarget(t, `{"permissions":{"allow":["Edit(*)"]}}`))
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 Warn, got %+v", f)
	}
}

func TestCFG002_UnrestrictedWrite(t *testing.T) {
	f := CFG002.Check(settingsTarget(t, `{"permissions":{"allow":["Write(*)"]}}`))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for Write(*), got %d", len(f))
	}
}

func TestCFG002_BothUnrestricted(t *testing.T) {
	f := CFG002.Check(settingsTarget(t, `{"permissions":{"allow":["Edit(*)","Write(*)"]}}`))
	if len(f) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(f))
	}
}

func TestCFG002_BareToolName_Unrestricted(t *testing.T) {
	for _, entry := range []string{"Edit", "Write"} {
		f := CFG002.Check(settingsTarget(t, `{"permissions":{"allow":["`+entry+`"]}}`))
		if len(f) != 1 || f[0].Severity != finding.Warn {
			t.Errorf("expected 1 Warn for bare %q, got %+v", entry, f)
		}
	}
}

func TestCFG002_CrossAgentConcreteGrants(t *testing.T) {
	for _, entry := range []string{
		"Edit(.cursor/mcp.json)",
		"Write(.codex/config.toml)",
		"Edit(.gemini/settings.json)",
		"Edit(C:/repo/.cursor/mcp.json)",
	} {
		target := settingsTarget(t, `{"permissions":{"allow":["`+entry+`"]}}`)
		v := version.Version{Major: 2, Minor: 1, Patch: 317}
		target.ClaudeVersion = &v
		f := CFG002.Check(target)
		if len(f) != 1 || !strings.Contains(f[0].Message, "configuration consumed by another agent") {
			t.Errorf("%s: expected cross-agent finding, got %+v", entry, f)
		}
	}
}

func TestCFG002_ClaudeSensitiveEditGate21317(t *testing.T) {
	v := version.Version{Major: 2, Minor: 1, Patch: 317}
	for _, entry := range []string{
		"Edit(.mcp.json)",
		"Edit(.vscode/settings.json)",
		"Edit(.vscode/tasks.json)",
	} {
		target := settingsTarget(t, `{"permissions":{"allow":["`+entry+`"]}}`)
		target.ClaudeVersion = &v
		if f := CFG002.Check(target); len(f) != 0 {
			t.Errorf("%s: sensitive-file gate should prevent a finding, got %+v", entry, f)
		}
	}
}

func TestCFG002_ClaudeSensitiveEditOlderOrUnknown(t *testing.T) {
	for _, versioned := range []bool{false, true} {
		target := settingsTarget(t, `{"permissions":{"allow":["Edit(.vscode/settings.json)"]}}`)
		if versioned {
			v := version.Version{Major: 2, Minor: 1, Patch: 316}
			target.ClaudeVersion = &v
		}
		if f := CFG002.Check(target); len(f) != 1 {
			t.Errorf("versioned=%v: expected finding, got %+v", versioned, f)
		}
	}
}

func TestCFG002_BroadEditNamesOnlyReachableConfigs(t *testing.T) {
	target := settingsTarget(t, `{"permissions":{"allow":["Edit(**)"]}}`)
	v := version.Version{Major: 2, Minor: 1, Patch: 317}
	target.ClaudeVersion = &v
	f := CFG002.Check(target)
	if len(f) != 1 {
		t.Fatalf("expected one finding, got %+v", f)
	}
	for _, want := range []string{".cursor/mcp.json", ".codex/config.toml"} {
		if !strings.Contains(f[0].Message, want) {
			t.Errorf("message does not name %s: %s", want, f[0].Message)
		}
	}
	for _, protected := range []string{".mcp.json", ".vscode/settings.json", ".vscode/tasks.json"} {
		if strings.Contains(f[0].Message, protected) {
			t.Errorf("message claims protected destination %s is reachable: %s", protected, f[0].Message)
		}
	}
}

func TestCFG002_WriteDoesNotAssumeEditProtection(t *testing.T) {
	target := settingsTarget(t, `{"permissions":{"allow":["Write(.vscode/settings.json)"]}}`)
	v := version.Version{Major: 2, Minor: 1, Patch: 317}
	target.ClaudeVersion = &v
	if f := CFG002.Check(target); len(f) != 1 {
		t.Fatalf("unmeasured Write tool must remain reported, got %+v", f)
	}
}

func TestCFG002_ScopedEdit_NoFinding(t *testing.T) {
	f := CFG002.Check(settingsTarget(t, `{"permissions":{"allow":["Edit(src/*)","Write(output/*)","Edit(**.go)"]}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding for scoped Edit/Write, got %d", len(f))
	}
}

func TestCFG002_NoPermissions_NoFinding(t *testing.T) {
	if f := CFG002.Check(settingsTarget(t, `{}`)); len(f) != 0 {
		t.Errorf("expected no finding when permissions absent, got %d", len(f))
	}
}

func TestCFG002_UnrestrictedBash_NoFinding(t *testing.T) {
	if f := CFG002.Check(settingsTarget(t, `{"permissions":{"allow":["Bash(*)"]}}`)); len(f) != 0 {
		t.Errorf("expected no CFG002 finding for Bash(*), got %d", len(f))
	}
}
