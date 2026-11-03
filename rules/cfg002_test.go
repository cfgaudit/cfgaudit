// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG002_UnrestrictedGrantsKeepStableMessage(t *testing.T) {
	for _, entry := range []string{"Edit", "Write", "Edit(*)", "Edit(**)", "Edit(./**)", "Edit(/**)"} {
		f := CFG002.Check(settingsTarget(t, `{"permissions":{"allow":["`+entry+`"]}}`))
		if len(f) != 1 || f[0].Severity != finding.Warn {
			t.Fatalf("%s: expected 1 Warn, got %+v", entry, f)
		}
		want := `permissions.allow contains "` + entry + `" — grants unrestricted file-write access; scope to specific directories`
		if f[0].Message != want {
			t.Errorf("%s: message changed\n got: %q\nwant: %q", entry, f[0].Message, want)
		}
	}
}

func TestCFG002_WriteSpecifierIsNotAGrant(t *testing.T) {
	for _, entry := range []string{"Write(*)", "Write(**)", "Write(./**)", "Write(.codex/config.toml)", "NotebookEdit(.cursor/mcp.json)"} {
		if f := CFG002.Check(settingsTarget(t, `{"permissions":{"allow":["`+entry+`"]}}`)); len(f) != 0 {
			t.Errorf("%s: path specifiers are ignored by this tool, got %+v", entry, f)
		}
	}
}

func TestCFG002_CrossAgentConcreteGrants(t *testing.T) {
	tests := []struct{ entry, path, agent string }{
		{"Edit(.cursor/mcp.json)", ".cursor/mcp.json", "Cursor"},
		{"Edit(.vscode/mcp.json)", ".vscode/mcp.json", "VS Code"},
		{"Edit(.github/hooks/pre.json)", ".github/hooks/*.json", "GitHub Copilot"},
		{"Edit(.devin/config.json)", ".devin/config.json", "Devin CLI"},
		{"Edit(opencode.json)", "opencode.json", "OpenCode"},
		{"Edit(.kiro/settings/mcp.json)", ".kiro/**", "Kiro"},
		{"Edit(.windsurf/hooks.json)", ".windsurf/**", "Windsurf"},
		{"Edit(.cline/rules/project.md)", ".cline/**", "Cline"},
	}
	for _, tt := range tests {
		f := CFG002.Check(settingsTarget(t, `{"permissions":{"allow":["`+tt.entry+`"]}}`))
		if len(f) != 1 || !strings.Contains(f[0].Message, tt.path+" ("+tt.agent+")") {
			t.Errorf("%s: expected named cross-agent finding, got %+v", tt.entry, f)
		}
	}
}

func TestCFG002_SensitiveEditFilesRemainReported(t *testing.T) {
	// An Edit(path) permission also authorizes Write tool calls. Only Edit tool
	// calls were measured against Claude's sensitive-file confirmation gate.
	for _, entry := range []string{"Edit(.mcp.json)", "Edit(.vscode/settings.json)", "Edit(.vscode/tasks.json)"} {
		if f := CFG002.Check(settingsTarget(t, `{"permissions":{"allow":["`+entry+`"]}}`)); len(f) != 1 {
			t.Errorf("%s: unmeasured Write call must remain reported, got %+v", entry, f)
		}
	}
}

func TestCFG002_ClaudePathGlobSemantics(t *testing.T) {
	for _, entry := range []string{
		"Edit(/.cursor/**)",
		"Edit(mcp.json)",
		"Edit(settings.json)",
		`Edit(.cursor\mcp.json)`,
		"Edit(.cursor/mcp.jso?)",
	} {
		jsonEntry := strings.ReplaceAll(entry, `\`, `\\`)
		if f := CFG002.Check(settingsTarget(t, `{"permissions":{"allow":["`+jsonEntry+`"]}}`)); len(f) != 1 {
			t.Errorf("%s: expected a finding, got %+v", entry, f)
		}
	}
	if f := CFG002.Check(settingsTarget(t, `{"permissions":{"allow":["Edit(.CURSOR/MCP.JSON)"]}}`)); len(f) != 0 {
		t.Errorf("path matching must remain case-sensitive, got %+v", f)
	}
}

func TestCFG002_EmptyOrScopedEdit_NoFinding(t *testing.T) {
	f := CFG002.Check(settingsTarget(t, `{"permissions":{"allow":["Edit()","Edit(src/*)","Edit(**.go)"]}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding for empty or scoped Edit, got %+v", f)
	}
}

func TestCFG002_DenyBeforeAllow(t *testing.T) {
	blocked := CFG002.Check(settingsTarget(t, `{"permissions":{"allow":["Edit(.cursor/**)"],"deny":["Edit(.cursor/**)"]}}`))
	if len(blocked) != 0 {
		t.Errorf("fully denied allow must not be reported, got %+v", blocked)
	}
	partial := CFG002.Check(settingsTarget(t, `{"permissions":{"allow":["Edit"],"deny":["Edit(.env)"]}}`))
	if len(partial) != 1 {
		t.Errorf("partial deny must leave broad allow reportable, got %+v", partial)
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
