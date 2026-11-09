// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/config"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func TestRooCommands(t *testing.T) {
	for _, tc := range []struct {
		name            string
		allowed, denied []string
		v               string
		want            bool
	}{
		{"prefix", nil, []string{"git push"}, "git push", true},
		{"shorter", nil, []string{"git"}, "git push", true},
		{"case", nil, []string{"GIT PUSH"}, "git push", true},
		{"star", nil, []string{"*"}, "git push", true},
		{"longer allow wins", []string{"git push"}, []string{"git"}, "git push", false},
		{"equal length denies", []string{"git push"}, []string{"git push"}, "git push", true},
		{"other", nil, []string{"git pull"}, "git push", false},
		{"none", nil, nil, "git push", false},
	} {
		p := &RooPolicy{Allowed: tc.allowed, Denied: tc.denied}
		if got := rooCommandCovered(p, tc.v); got != tc.want {
			t.Errorf("%s: got %v", tc.name, got)
		}
	}
	for _, tc := range []struct {
		allowed, denied []string
		v               string
		want            bool
	}{
		{[]string{"curl"}, nil, "curl", true},
		{[]string{"*"}, nil, "curl", true},
		{[]string{"curl -s"}, nil, "curl", true},
		{[]string{"curl"}, []string{"curl"}, "curl", false},
		{[]string{"*"}, []string{"curl"}, "curl", false},
		{[]string{"git"}, nil, "curl", false},
	} {
		if _, got := rooCommandGrant(&RooPolicy{Allowed: tc.allowed, Denied: tc.denied}, tc.v); got != tc.want {
			t.Errorf("grant %v %v: got %v", tc.allowed, tc.denied, got)
		}
	}
}

func TestRooIgnored(t *testing.T) {
	for _, tc := range []struct {
		ignore, v string
		want      bool
	}{
		{".env\n", "**/.env", true},
		{"**/.env\n", "**/.env", true},
		{"# .env\n\n", "**/.env", false},
		{"src/\n", "src/generated/**", true},
		{"src/generated/**\n", "src/generated/**", true},
		{"/src/generated/\n", "src/generated/**", true},
		{"lib/\n", "src/generated/**", false},
		{".env\n!.env\n", "**/.env", false},
		{"!.env\n.env\n", "**/.env", true},
	} {
		if got := rooIgnored(tc.ignore, tc.v); got != tc.want {
			t.Errorf("%q %s: got %v", tc.ignore, tc.v, got)
		}
	}
}

func TestCFG025_Roo(t *testing.T) {
	tg := &Target{PolicyAgent: "roo-code", PolicyRoo: &RooPolicy{
		SettingsFile: "s", IgnoreFile: "i", MCPFile: "m",
		Allowed: []string{"curl"},
		MCP: map[string]parser.MCPServer{
			"gh":  {DisabledTools: []string{"delete_repo"}, AlwaysAllow: []string{"get_pr"}},
			"off": {Disabled: true},
		},
	},
		PolicyDeny: config.PolicyRules{
			Commands: []string{"git push"}, Read: []string{"**/.env", "~/.ssh/**"}, Fetch: []string{"example.com"},
			MCPTools: []string{"gh:delete_repo", "gh:delete_*", "gh:other", "off:x", "absent:x"},
		},
		PolicyForbid: config.PolicyRules{Commands: []string{"curl"}, MCPTools: []string{"gh:get_pr"}},
	}
	f := CFG025.Check(tg)
	got := messages(f)
	for _, want := range []string{
		`policy deny.commands "git push": nothing covers it, so Roo Code does not block it; add "git push" to roo-cline.deniedCommands, with no longer prefix in roo-cline.allowedCommands`,
		`policy deny.read "**/.env": nothing covers it, so Roo Code does not block it; add the line **/.env to .rooignore`,
		`add each matching tool to disabledTools of gh`,
		`add "other" to disabledTools of gh`,
		`policy forbid-allow.commands "curl": roo-cline.allowedCommands grants it via "curl", so Roo Code runs it without asking when auto-execute is on`,
		`policy forbid-allow.mcp-tools "gh:get_pr": alwaysAllow grants it via "get_pr", so Roo Code runs it without asking`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if len(f) != 6 {
		t.Errorf("want 6 findings, got:\n%s", got)
	}
}

func TestRooMCPGrant(t *testing.T) {
	s := map[string]parser.MCPServer{"gh": {AlwaysAllow: []string{"*"}}, "safe": {AlwaysAllow: []string{"read"}}}
	if _, ok := rooMCPGrant(s, "gh:x"); !ok {
		t.Error("wildcard")
	}
	if _, ok := rooMCPGrant(s, "safe:write"); ok {
		t.Error("other tool")
	}
}

func TestCFG025_Gemini(t *testing.T) {
	tg := &Target{PolicyAgent: "gemini-cli", PolicyFile: "g", PolicyGeminiAllowed: []string{"run_shell_command(curl)", "read_file"},
		PolicyForbid: config.PolicyRules{Commands: []string{"curl", "wget"}}}
	f := CFG025.Check(tg)
	if len(f) != 1 || !strings.Contains(f[0].Message, `tools.allowed grants it via "run_shell_command(curl)"`) {
		t.Fatalf("got:\n%s", messages(f))
	}
}

func TestCFG025_Antigravity(t *testing.T) {
	tg := &Target{PolicyAgent: "antigravity", PolicyFile: "m",
		PolicyMCP:  map[string]parser.MCPServer{"gh": {DisabledTools: []string{"delete_repo"}}},
		PolicyDeny: config.PolicyRules{MCPTools: []string{"gh:delete_repo", "gh:create", "absent:x"}},
	}
	f := CFG025.Check(tg)
	if len(f) != 1 || f[0].File != "m" || !strings.Contains(f[0].Message, `add "create" to disabledTools of gh`) {
		t.Fatalf("got:\n%s", messages(f))
	}
}
