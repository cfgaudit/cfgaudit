// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/config"
	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

// Which deny entries cover a neutral policy entry, in each agent's syntax
// (#1081). Each row is checked in both directions: covered and not covered.
func TestPolicySpellings_Covers(t *testing.T) {
	cases := []struct {
		agent, category, value string
		covered, notCovered    []string
	}{
		{"claude-code", "commands", "git push",
			[]string{"Bash(git push *)", "Bash(git push:*)", "Bash(git:*)", "Bash(git *)", "Bash(*)", "Bash"},
			[]string{"Bash(git push)", "Bash(git push --force *)", "Bash(gitk:*)", "Exec(git push)", "Read(git push)"}},
		{"claude-code", "read", "**/.env",
			[]string{"Read(**/.env)", "Read(.env)", "Read(./.env)", "Read(**)", "Read"},
			[]string{"Read(.env.local)", "Edit(**/.env)", "Read(src/**)"}},
		{"claude-code", "read", "~/.ssh/**",
			[]string{"Read(~/.ssh/**)", "Read(~/**)", "Read"},
			[]string{"Read(**)", "Read(.ssh/**)"}},
		{"claude-code", "write", "src/generated/**",
			[]string{"Edit(src/generated/**)", "Edit(src/**)", "Read(src/**)", "Edit", "Read"},
			[]string{"Write(src/generated/**)", "Edit(src/generated/*.ts)"}},
		{"claude-code", "fetch", "*.example.com",
			[]string{"WebFetch(domain:*.example.com)", "WebFetch(domain:*)", "WebFetch(domain:*.com)", "WebFetch"},
			[]string{"WebFetch(domain:example.com)", "WebFetch(domain:api.example.com)", "Fetch(domain:*.example.com)"}},
		{"claude-code", "fetch", "api.example.com",
			[]string{"WebFetch(domain:api.example.com)", "WebFetch(domain:*.example.com)"},
			[]string{"WebFetch(domain:example.com)"}},
		{"claude-code", "mcp-tools", "github:delete_*",
			[]string{"mcp__github", "mcp__github__*", "mcp__github__delete_*", "mcp__github__del*", "mcp__*"},
			[]string{"mcp__github__delete_repo", "mcp__gitlab__*", "mcp__github(delete_*)"}},
		{"claude-code", "mcp-tools", "my.server:run",
			[]string{"mcp__my_server__run", "mcp__my_server"},
			[]string{"mcp__my.server__run"}},
		{"devin", "commands", "git push",
			[]string{"Exec(git push)", "Exec(git)", "exec"},
			[]string{"Exec(git push --force)", "Exec(gi)", "Bash(git push:*)"}},
		{"devin", "read", "**/.env",
			[]string{"Read(**/.env)", "Read(**)", "read"},
			[]string{"Read(.env)", "Write(**/.env)"}},
		{"devin", "write", "src/generated/**",
			[]string{"Write(src/generated/**)", "Write(src/**)", "edit"},
			[]string{"Edit(src/generated/**)", "Read(src/**)"}},
		{"devin", "fetch", "*.example.com",
			[]string{"Fetch(https://*.example.com/*)"},
			[]string{"Fetch(domain:*.example.com)", "Fetch(domain:example.com)", "Fetch(https://*.example.com/api/*)"}},
		{"devin", "fetch", "npmjs.org",
			[]string{"Fetch(domain:npmjs.org)", "Fetch(https://npmjs.org/*)"},
			[]string{"Fetch(domain:registry.npmjs.org)"}},
		{"devin", "mcp-tools", "github:delete_*",
			[]string{"mcp__github__*", "mcp__github__delete_*", "mcp__*"},
			[]string{"mcp__github", "mcp__github__delete_repo"}},
	}
	for _, tc := range cases {
		sp := policySpellings[tc.agent]
		for _, e := range tc.covered {
			if !sp.covers(tc.category, e, tc.value) {
				t.Errorf("%s %s %q: %q should cover it", tc.agent, tc.category, tc.value, e)
			}
		}
		for _, e := range tc.notCovered {
			if sp.covers(tc.category, e, tc.value) {
				t.Errorf("%s %s %q: %q should not cover it", tc.agent, tc.category, tc.value, e)
			}
		}
		// The entry the message suggests must satisfy the check.
		if s := sp.spell(tc.category, tc.value); !sp.covers(tc.category, s, tc.value) {
			t.Errorf("%s %s %q: suggested %q does not cover it", tc.agent, tc.category, tc.value, s)
		}
	}
}

// Which allow entries grant something a neutral forbid-allow entry names.
func TestPolicySpellings_Overlaps(t *testing.T) {
	cases := []struct {
		agent, category, value string
		grants, notGrants      []string
	}{
		{"claude-code", "commands", "curl",
			[]string{"Bash(curl:*)", "Bash(curl https://x)", "Bash(*)", "Bash"},
			[]string{"Bash(curly)", "Bash(git:*)", "Exec(curl)"}},
		{"claude-code", "mcp-tools", "github:*",
			[]string{"mcp__github", "mcp__github__create_issue", "mcp__github__get_*"},
			[]string{"mcp__*", "mcp__gitlab__x"}},
		{"claude-code", "mcp-tools", "github:delete_repo",
			[]string{"mcp__github__delete_repo", "mcp__github__delete_*", "mcp__github__*"},
			[]string{"mcp__github__get_*", "mcp__github__delete_branch"}},
		{"devin", "commands", "git push",
			[]string{"Exec(git)", "Exec(git push)", "Exec(git push origin)", "exec"},
			[]string{"Exec(git status)", "Exec(gitk)"}},
		{"devin", "mcp-tools", "github:delete_*",
			[]string{"mcp__*", "mcp__github__*", "mcp__github__delete_repo"},
			[]string{"mcp__github", "mcp__github__get_*"}},
	}
	for _, tc := range cases {
		sp := policySpellings[tc.agent]
		for _, e := range tc.grants {
			if !sp.overlaps(tc.category, e, tc.value) {
				t.Errorf("%s %s %q: allow %q should grant it", tc.agent, tc.category, tc.value, e)
			}
		}
		for _, e := range tc.notGrants {
			if sp.overlaps(tc.category, e, tc.value) {
				t.Errorf("%s %s %q: allow %q should not grant it", tc.agent, tc.category, tc.value, e)
			}
		}
	}
}

func messages(fs []finding.Finding) string {
	var b strings.Builder
	for _, f := range fs {
		b.WriteString(f.File + ": " + f.Message + "\n")
	}
	return b.String()
}

func TestCFG025_NeutralPolicy_Claude(t *testing.T) {
	tg := settingsTarget(t, `{"permissions":{"deny":["Bash(git:*)","Read(.env)"],"allow":["Bash(curl:*)","mcp__*"]}}`)
	tg.Scope = finding.ScopeProject
	tg.PolicyAgent = "claude-code"
	tg.PolicyDeny = config.PolicyRules{Commands: []string{"git push", "rm -rf"}, Read: []string{"**/.env"}}
	tg.PolicyForbid = config.PolicyRules{Commands: []string{"curl"}, MCPTools: []string{"github:*"}}
	f := CFG025.Check(tg)
	got := messages(f)
	if len(f) != 2 ||
		!strings.Contains(got, `test/settings.json: policy deny.commands "rm -rf": no permissions.deny entry covers it, so Claude Code does not block it; add "Bash(rm -rf *)"`) ||
		!strings.Contains(got, `policy forbid-allow.commands "curl": permissions.allow grants it via "Bash(curl:*)", so Claude Code runs it without asking`) {
		t.Fatalf("got:\n%s", got)
	}
}

// A settings file Claude Code discards whole denies nothing and allows
// nothing, and the message says why.
func TestCFG025_NeutralPolicy_ClaudeDiscarded(t *testing.T) {
	tg := settingsTarget(t, `{"permissions":{"deny":["Bash(git:*)"],"allow":["Bash(curl:*)"]},"env":"x"}`)
	if !tg.discarded() {
		t.Fatal("fixture is no longer discarded; pick another type mismatch")
	}
	tg.PolicyAgent = "claude-code"
	tg.PolicyDeny = config.PolicyRules{Commands: []string{"git push"}}
	tg.PolicyForbid = config.PolicyRules{Commands: []string{"curl"}}
	f := CFG025.Check(tg)
	if len(f) != 1 || !strings.Contains(f[0].Message, "discards this settings file whole") {
		t.Fatalf("got:\n%s", messages(f))
	}
}

func TestCFG025_NeutralPolicy_Devin(t *testing.T) {
	tg := &Target{
		Scope:     finding.ScopeProject,
		DevinFile: ".devin/config.json",
		Devin: &parser.DevinConfig{Permissions: &parser.Permissions{
			Allow: []string{"Exec(git)"}, Deny: []string{"Exec(rm)", "Fetch(https://*.example.com/*)"},
		}},
		PolicyAgent:  "devin",
		PolicyDeny:   config.PolicyRules{Commands: []string{"rm -rf", "git push"}, Fetch: []string{"*.example.com"}, MCPTools: []string{"github:delete_*"}},
		PolicyForbid: config.PolicyRules{Commands: []string{"git push"}},
	}
	got := messages(CFG025.Check(tg))
	for _, want := range []string{
		`.devin/config.json: policy deny.commands "git push": no permissions.deny entry covers it, so Devin CLI does not block it; add "Exec(git push)"`,
		`policy deny.mcp-tools "github:delete_*": no permissions.deny entry covers it, so Devin CLI does not block it; add "mcp__github__delete_*"`,
		`policy forbid-allow.commands "git push": permissions.allow grants it via "Exec(git)", so Devin CLI runs it without asking`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Count(got, "\n") != 3 {
		t.Errorf("want 3 findings, got:\n%s", got)
	}
	// A Devin target with no permissions at all reports every deny entry.
	tg.Devin = &parser.DevinConfig{}
	if f := CFG025.Check(tg); len(f) != 4 {
		t.Errorf("empty Devin config: want 4 findings, got:\n%s", messages(f))
	}
}

// Without PolicyAgent the neutral entries are not checked, so a target that
// is not an agent's permission file never reports them.
func TestCFG025_NeutralPolicy_NoAgent(t *testing.T) {
	tg := &Target{Scope: finding.ScopeProject, PolicyDeny: config.PolicyRules{Commands: []string{"git push"}}}
	if f := CFG025.Check(tg); len(f) != 0 {
		t.Fatalf("got:\n%s", messages(f))
	}
}

func TestCFG118(t *testing.T) {
	tg := &Target{
		Scope:               finding.ScopeProject,
		PolicyDeny:          config.PolicyRules{Commands: []string{"git push"}, Read: []string{"**/.env"}},
		PolicyUnenforceable: []UnenforceableAgent{{Agent: "zed", Name: "Zed", Dir: ".zed"}, {Agent: "continue", Name: "Continue", Dir: ".continue"}},
	}
	f := CFG118.Check(tg)
	if len(f) != 2 || f[0].Severity != finding.Info || f[0].File != ".zed" ||
		f[0].Message != "policy deny.commands, deny.read cannot be enforced for Zed from the repository: Zed reads its permission rules from user settings only, so each contributor has to add the rules to their own settings" {
		t.Fatalf("got:\n%s", messages(f))
	}
	tg.PolicyDeny = config.PolicyRules{}
	if f := CFG118.Check(tg); len(f) != 0 {
		t.Fatalf("no deny entries: got:\n%s", messages(f))
	}
}
