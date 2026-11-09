// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/config"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func TestOrderedWildcard(t *testing.T) {
	for _, tc := range []struct {
		input, pattern string
		want           bool
	}{
		{"git push", "git push *", true},
		{"git push origin", "git push *", true},
		{"git pushx", "git push *", false},
		{"git push origin", "git push", false},
		{".env", "**/.env", false},
		{"a/.env", "**/.env", true},
		{".env", "*.env", true},
		{"a.b", "a?b", true},
		{"axb", "a.b", false},
	} {
		if got := orderedWildcard(tc.input, tc.pattern); got != tc.want {
			t.Errorf("%q %q: got %v", tc.input, tc.pattern, got)
		}
	}
}

func rule(action, resource, effect string) orderedRule {
	return orderedRule{Action: action, Resource: resource, Effect: effect}
}

// The order decides: a later allow reopens a deny, and a later deny closes an
// allow (#1515).
func TestOrderedDenied(t *testing.T) {
	cases := []struct {
		name          string
		rules         []orderedRule
		category, v   string
		urls, covered bool
	}{
		{"deny", []orderedRule{rule("bash", "git push *", "deny")}, "commands", "git push", false, true},
		{"later allow reopens", []orderedRule{rule("bash", "git push *", "deny"), rule("bash", "git *", "allow")}, "commands", "git push", false, false},
		{"later deny closes", []orderedRule{rule("bash", "git *", "allow"), rule("bash", "git push *", "deny")}, "commands", "git push", false, true},
		{"exact misses args", []orderedRule{rule("bash", "git push", "deny")}, "commands", "git push", false, false},
		{"whole tool", []orderedRule{rule("bash", "*", "deny")}, "commands", "git push", false, true},
		{"everything", []orderedRule{rule("*", "*", "deny")}, "commands", "git push", false, true},
		{"nothing", nil, "commands", "git push", false, false},
		{"star env", []orderedRule{rule("read", "*.env", "deny")}, "read", "**/.env", false, true},
		{"double star misses root", []orderedRule{rule("read", "**/.env", "deny")}, "read", "**/.env", false, false},
		{"dir", []orderedRule{rule("edit", "src/generated/*", "deny")}, "write", "src/generated/**", false, true},
		{"read is not edit", []orderedRule{rule("read", "src/*", "deny")}, "write", "src/generated/**", false, false},
		{"home", []orderedRule{rule("external_directory", "~/.ssh/**", "deny")}, "read", "~/.ssh/**", false, true},
		{"home spelled", []orderedRule{rule("external_directory", "$HOME/.ssh/**", "deny")}, "read", "~/.ssh/**", false, true},
		{"home via read", []orderedRule{rule("read", "~/.ssh/**", "deny")}, "read", "~/.ssh/**", false, false},
		{"kilo fetch", []orderedRule{rule("webfetch", "*://*.example.com/*", "deny")}, "fetch", "*.example.com", true, true},
		{"kilo fetch other", []orderedRule{rule("webfetch", "*://example.org/*", "deny")}, "fetch", "example.com", true, false},
		{"mcp", []orderedRule{rule("github_delete_*", "*", "deny")}, "mcp-tools", "github:delete_*", false, true},
		{"mcp other", []orderedRule{rule("gitlab_*", "*", "deny")}, "mcp-tools", "github:delete_*", false, false},
	}
	for _, tc := range cases {
		if got := orderedDenied(tc.rules, tc.category, tc.v, tc.urls); got != tc.covered {
			t.Errorf("%s: got %v", tc.name, got)
		}
	}
}

// Every suggested rule, written as the agent reads it, satisfies the check.
func TestOrderedSpell(t *testing.T) {
	for _, tc := range []struct {
		category, v, want string
		urls              bool
		rule              orderedRule
	}{
		{"commands", "git push", `"git push *": "deny" under "bash"`, false, rule("bash", "git push *", "deny")},
		{"read", "**/.env", `"*.env": "deny" under "read"`, false, rule("read", "*.env", "deny")},
		{"write", "src/generated/**", `"src/generated/*": "deny" under "edit"`, false, rule("edit", "src/generated/*", "deny")},
		{"read", "~/.ssh/**", `"~/.ssh/**": "deny" under "external_directory"`, false, rule("external_directory", "~/.ssh/**", "deny")},
		{"fetch", "*.example.com", `"*://*.example.com/*": "deny" under "webfetch"`, true, rule("webfetch", "*://*.example.com/*", "deny")},
		{"mcp-tools", "github:delete_*", `"github_delete_*": "deny"`, false, rule("github_delete_*", "*", "deny")},
		{"read", ".cfg", `".cfg": "deny" under "read"`, false, rule("read", ".cfg", "deny")},
	} {
		if got := orderedSpell(tc.category, tc.v, tc.urls); got != tc.want {
			t.Errorf("%s %s: got %s", tc.category, tc.v, got)
		}
		if !orderedDenied([]orderedRule{tc.rule}, tc.category, tc.v, tc.urls) {
			t.Errorf("%s %s: the suggested rule does not cover it", tc.category, tc.v)
		}
	}
}

func TestOrderedGrant(t *testing.T) {
	for _, tc := range []struct {
		name     string
		rules    []orderedRule
		category string
		v        string
		want     bool
	}{
		{"broad", []orderedRule{rule("bash", "curl *", "allow")}, "commands", "curl", true},
		{"narrow", []orderedRule{rule("bash", "git push --tags", "allow")}, "commands", "git push", true},
		{"narrow then denied", []orderedRule{rule("bash", "git push --tags", "allow"), rule("bash", "git *", "deny")}, "commands", "git push", false},
		{"denied after", []orderedRule{rule("bash", "curl *", "allow"), rule("bash", "curl *", "deny")}, "commands", "curl", false},
		{"other", []orderedRule{rule("bash", "git *", "allow")}, "commands", "curl", false},
		{"ask", []orderedRule{rule("bash", "curl *", "ask")}, "commands", "curl", false},
		{"mcp", []orderedRule{rule("github_get_*", "*", "allow")}, "mcp-tools", "github:*", true},
		{"mcp other", []orderedRule{rule("gitlab_get_*", "*", "allow")}, "mcp-tools", "github:*", false},
	} {
		if _, got := orderedGrant(tc.rules, tc.category, tc.v, false); got != tc.want {
			t.Errorf("%s: got %v", tc.name, got)
		}
	}
}

func TestCFG025_OrderedPolicy(t *testing.T) {
	tg := &Target{
		PolicyAgent: "kilo-code", PolicyFile: "kilo.jsonc",
		PolicyBlocks: []parser.OpenCodePermissionBlock{
			{Where: "permission", Rules: []orderedRule{rule("bash", "git push *", "deny"), rule("bash", "curl *", "allow")}},
			{Where: "agent.ops.permission", Rules: []orderedRule{rule("bash", "git *", "allow")}},
		},
		PolicyDeny:   config.PolicyRules{Commands: []string{"git push"}},
		PolicyForbid: config.PolicyRules{Commands: []string{"curl"}},
	}
	got := messages(CFG025.Check(tg))
	for _, want := range []string{
		`policy deny.commands "git push": no rule denies it as the last match in agent.ops.permission, so Kilo Code does not block it; add "git push *": "deny" under "bash" after the rules it has to override`,
		`policy forbid-allow.commands "curl": "bash" rule "curl *" allows it, so Kilo Code runs it without asking`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	// An OpenCode 2 rule is named as the file spells it (#748).
	tg.PolicyBlocks = append(tg.PolicyBlocks, parser.OpenCodePermissionBlock{Where: "permissions", Rules: []orderedRule{{Action: "bash", Resource: "curl *", Effect: "allow", Native: "shell"}}})
	if got := messages(CFG025.Check(tg)); !strings.Contains(got, `"shell" rule "curl *" allows it`) {
		t.Errorf("native spelling missing:\n%s", got)
	}
	tg.PolicyAgent = "opencode"
	tg.PolicyDeny = config.PolicyRules{Fetch: []string{"example.com"}}
	tg.PolicyForbid = config.PolicyRules{}
	if f := CFG025.Check(tg); len(f) != 0 {
		t.Fatalf("OpenCode fetch goes to CFG118: %s", messages(f))
	}
}

func TestOrderedDeniesFetch(t *testing.T) {
	off := []parser.OpenCodePermissionBlock{{Where: "permission", Rules: []orderedRule{rule("webfetch", "*", "deny")}}}
	if !OrderedDeniesFetch(off) {
		t.Error("tool off")
	}
	if OrderedDeniesFetch(append(off, parser.OpenCodePermissionBlock{Where: "agent.a.permission", Rules: []orderedRule{rule("webfetch", "*", "allow")}})) {
		t.Error("an agent turns it back on")
	}
	if OrderedDeniesFetch(nil) {
		t.Error("no rules")
	}
}
