// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/cfgaudit/cfgaudit/internal/config"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func codexConfig(t *testing.T, src string) *parser.CodexConfig {
	t.Helper()
	var c parser.CodexConfig
	if _, err := toml.Decode(src, &c); err != nil {
		t.Fatal(err)
	}
	return &c
}

func TestCodexCommands(t *testing.T) {
	forbid := parser.ParseCodexRules(`prefix_rule(pattern=["git", ["push", "fetch"]], decision="forbidden")`)
	if !codexForbidden(forbid, "git push") || !codexForbidden(forbid, "git fetch origin") || codexForbidden(forbid, "git") || codexForbidden(forbid, "gitk") {
		t.Fatal("forbidden prefix")
	}
	if codexForbidden(parser.ParseCodexRules(`prefix_rule(pattern=["git", "push"], decision="prompt")`), "git push") {
		t.Fatal("prompt is not forbidden")
	}
	for src, want := range map[string]bool{
		`prefix_rule(pattern=["curl"])`:                                                            true,
		`prefix_rule(pattern=["curl", "-s"])`:                                                      true,
		`prefix_rule(pattern=["curl"], decision="prompt")`:                                         false,
		`prefix_rule(pattern=["wget"])`:                                                            false,
		"prefix_rule(pattern=[\"curl\"])\nprefix_rule(pattern=[\"curl\"], decision=\"forbidden\")": false,
	} {
		if _, got := codexCommandGrant(parser.ParseCodexRules(src), "curl"); got != want {
			t.Errorf("%s: got %v", src, got)
		}
	}
}

func TestCodexPaths(t *testing.T) {
	c := codexConfig(t, `
default_permissions = "child"
[permissions.child]
extends = "base"
[permissions.child.filesystem.":workspace_roots"]
"**/.env" = "deny"
"src/generated/**" = "read"
[permissions.base.filesystem]
"~/.ssh" = "none"
"~/.aws/**" = "write"
`)
	p := c.SelectedPermissionProfiles()
	for _, tc := range []struct {
		category, v string
		want        bool
	}{
		{"read", "**/.env", true},
		{"write", "**/.env", true},
		{"read", "~/.ssh/**", true},
		{"read", "~/.ssh/id_rsa", true},
		{"read", "~/.aws/**", false},
		{"write", "src/generated/**", true},
		{"write", "src/generated/a/**", true},
		{"read", "src/generated/**", false},
		{"read", "**/secrets", false},
	} {
		if got := codexPathDenied(p, tc.category, tc.v); got != tc.want {
			t.Errorf("%s %s: got %v", tc.category, tc.v, got)
		}
	}
	// A scope other than the workspace says nothing about a repository path.
	c = codexConfig(t, "default_permissions = \"p\"\n[permissions.p.filesystem.\":tmpdir\"]\n\"**/.env\" = \"deny\"\n")
	if codexPathDenied(c.SelectedPermissionProfiles(), "read", "**/.env") {
		t.Error("tmpdir scope")
	}
	for src, v := range map[string]string{
		`":root" = "deny"`:            "**/.env",
		`":workspace_roots" = "none"`: "src/**",
	} {
		c := codexConfig(t, "default_permissions = \"p\"\n[permissions.p.filesystem]\n"+src+"\n")
		if !codexPathDenied(c.SelectedPermissionProfiles(), "read", v) {
			t.Errorf("%s: %s not denied", src, v)
		}
	}
}

func TestCodexFetch(t *testing.T) {
	c := codexConfig(t, `
default_permissions = "p"
[permissions.p.network]
enabled = true
[permissions.p.network.domains]
"**.example.com" = "deny"
"github.com" = "allow"
`)
	p := c.SelectedPermissionProfiles()
	if !codexFetchDenied(p, "*.example.com") || !codexFetchDenied(p, "api.example.com") || codexFetchDenied(p, "github.com") {
		t.Fatal("domains")
	}
	if codexFetchDenied(codexConfig(t, "default_permissions = \"p\"\n[permissions.p]\n").SelectedPermissionProfiles(), "example.com") {
		t.Fatal("no network block")
	}
	off := codexConfig(t, "default_permissions = \"p\"\n[permissions.p.network]\nenabled = false\n")
	if !codexFetchDenied(off.SelectedPermissionProfiles(), "example.com") {
		t.Fatal("network off")
	}
	if codexFetchDenied(nil, "example.com") {
		t.Fatal("no profile")
	}
}

func TestCodexMCP(t *testing.T) {
	c := codexConfig(t, `
[mcp_servers.gh]
command = "x"
disabled_tools = ["delete_repo"]
[mcp_servers.gh.tools.get_pr]
approval_mode = "approve"
[mcp_servers.only]
command = "x"
enabled_tools = ["read"]
[mcp_servers.off]
command = "x"
enabled = false
[mcp_servers.open]
command = "x"
default_tools_approval_mode = "approve"
`)
	s := c.MCPServers
	for v, want := range map[string]bool{
		"gh:delete_repo": true, "gh:delete_*": false, "gh:other": false,
		"only:write": true, "only:read": false, "only:re*": false,
		"off:anything": true, "absent:tool": true,
	} {
		if got := codexMCPDenied(s, v); got != want {
			t.Errorf("%s: got %v", v, got)
		}
	}
	for v, want := range map[string]bool{"gh:get_pr": true, "gh:get_*": true, "gh:other": false, "open:x": true, "absent:x": false} {
		if _, got := codexMCPGrant(s, v); got != want {
			t.Errorf("grant %s: got %v", v, got)
		}
	}
	if got := codexMCPSpell(s, "gh:delete_repo"); got != `"delete_repo" to disabled_tools under [mcp_servers.gh]` {
		t.Error(got)
	}
	if got := codexMCPSpell(s, "gh:delete_*"); !strings.HasPrefix(got, "each matching tool") {
		t.Error(got)
	}
}

func TestCFG025_Codex(t *testing.T) {
	tg := &Target{
		PolicyAgent: "codex", CodexFile: ".codex/config.toml", CodexRulesFile: ".codex/rules/default.rules",
		Codex:      codexConfig(t, "[mcp_servers.gh]\ncommand = \"x\"\ndefault_tools_approval_mode = \"approve\"\n"),
		CodexRules: parser.ParseCodexRules(`prefix_rule(pattern=["curl"])`),
		PolicyDeny: config.PolicyRules{
			Commands: []string{"git push"}, Read: []string{"**/.env"}, Write: []string{"src/**"},
			Fetch: []string{"*.example.com"}, MCPTools: []string{"gh:delete_repo"},
		},
		PolicyForbid: config.PolicyRules{Commands: []string{"curl"}, MCPTools: []string{"gh:*"}},
	}
	got := messages(CFG025.Check(tg))
	for _, want := range []string{
		`policy deny.commands "git push": nothing covers it, so Codex does not block it; add prefix_rule(pattern=["git", "push"], decision="forbidden") to a file in .codex/rules/`,
		`policy deny.read "**/.env": nothing covers it, so Codex does not block it; add "**/.env" = "deny" under [permissions.policy.filesystem.":workspace_roots"], with default_permissions = "policy"`,
		`policy deny.write "src/**": nothing covers it, so Codex does not block it; add "src/**" = "read" under [permissions.policy.filesystem.":workspace_roots"], with default_permissions = "policy"`,
		`policy deny.fetch "*.example.com": nothing covers it, so Codex does not block it; add "*.example.com" = "deny" under [permissions.policy.network.domains], with default_permissions = "policy"`,
		`policy deny.mcp-tools "gh:delete_repo": nothing covers it, so Codex does not block it; add "delete_repo" to disabled_tools under [mcp_servers.gh]`,
		`policy forbid-allow.commands "curl": the allow rule "curl" grants it, so Codex runs it without asking`,
		`policy forbid-allow.mcp-tools "gh:*": default_tools_approval_mode = "approve" grants it, so Codex runs it without asking`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	// A named profile needs no selection note, and a home path goes in the
	// filesystem table.
	p := codexConfig(t, "default_permissions = \"team\"\n[permissions.team]\n").SelectedPermissionProfiles()
	if got := codexPathSpell(p, "read", "~/.ssh/**"); got != `"~/.ssh" = "deny" under [permissions.team.filesystem]` {
		t.Error(got)
	}
}
