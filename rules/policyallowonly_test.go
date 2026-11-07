// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/config"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func TestCFG025_CursorIDE(t *testing.T) {
	tg := &Target{
		PolicyAgent: "cursor", CursorPermissionsFile: "p",
		CursorPermissions: &parser.CursorPermissions{
			TerminalAllowlist: []string{"curl:*", "git status"},
			MCPAllowlist:      []string{"github:*"},
		},
		PolicyForbid: config.PolicyRules{Commands: []string{"curl", "rm"}, MCPTools: []string{"github:delete_*", "gitlab:*"}},
	}
	f := CFG025.Check(tg)
	got := messages(f)
	if len(f) != 2 ||
		!strings.Contains(got, `policy forbid-allow.commands "curl": terminalAllowlist grants it via "curl:*", so Cursor runs it without asking`) ||
		!strings.Contains(got, `policy forbid-allow.mcp-tools "github:delete_*": mcpAllowlist grants it via "github:*"`) {
		t.Fatalf("got:\n%s", got)
	}
	tg.CursorPermissions = nil
	if f := CFG025.Check(tg); len(f) != 0 {
		t.Fatalf("no file: %s", messages(f))
	}
}

func TestVSCodeMatches(t *testing.T) {
	for _, tc := range []struct {
		key, v           string
		matches, decided bool
	}{
		{"curl", "curl", true, true},
		{"curl -s", "curl", true, true},
		{"curly", "curl", false, true},
		{"git", "git push", true, true},
		{"/^git\\b/", "git push", true, true},
		{"/^GIT/i", "git push", true, true},
		{"/^git push -/", "git push", false, true},
		{"/^npm/", "git push", false, true},
		{"/(?<=a)b/", "git push", false, false},
	} {
		m, d := vscodeMatches(tc.key, tc.v)
		if m != tc.matches || d != tc.decided {
			t.Errorf("%q %q: got %v %v", tc.key, tc.v, m, d)
		}
	}
}

func vscodeSettings(t *testing.T, src string) *parser.VSCodeSettings {
	t.Helper()
	s, err := parser.ParseVSCodeSettingsBytes([]byte(src), "settings.json")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCFG025_VSCode(t *testing.T) {
	check := func(src string, forbid ...string) string {
		return messages(CFG025.Check(&Target{
			PolicyAgent: "vscode", VSCodeSettingsFile: "s", VSCodeSettings: vscodeSettings(t, src),
			PolicyForbid: config.PolicyRules{Commands: forbid},
		}))
	}
	if got := check(`{"chat.tools.terminal.autoApprove":{"curl":true}}`, "curl"); !strings.Contains(got, `grants it via "curl", so VS Code runs it without asking`) {
		t.Errorf("got:\n%s", got)
	}
	if got := check(`{"chat.tools.terminal.autoApprove":{"curl":true,"curl -s":false}}`, "curl -s"); got != "" {
		t.Errorf("a false entry keeps the prompt:\n%s", got)
	}
	if got := check(`{"chat.tools.terminal.autoApprove":{"curl":true,"curl -s":false}}`, "curl"); !strings.Contains(got, `grants it via "curl"`) {
		t.Errorf("a narrower false entry leaves the rest granted:\n%s", got)
	}
	if got := check(`{"chat.tools.terminal.autoApprove":{"/(?<=a)b/":true}}`, "curl"); !strings.Contains(got, "cfgaudit cannot read") {
		t.Errorf("got:\n%s", got)
	}
	if got := check(`{"chat.tools.terminal.autoApprove":{"git":true}}`, "curl"); got != "" {
		t.Errorf("got:\n%s", got)
	}
	if got := check(`{"editor.tabSize":2}`, "curl"); got != "" {
		t.Errorf("got:\n%s", got)
	}
	if f := CFG025.Check(&Target{PolicyAgent: "vscode"}); len(f) != 0 {
		t.Errorf("no settings: %s", messages(f))
	}
}
