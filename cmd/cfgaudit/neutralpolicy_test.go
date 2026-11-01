// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

// policyFindings scans root with only the policy rules and returns
// "file|rule|message" lines, sorted, with root stripped.
func policyFindings(t *testing.T, root string) []string {
	t.Helper()
	code, out, errOut := runCLI(t, "--claude-version", "2.1.316", "--only", "CFG025,CFG118", "--format", "json", root)
	if code == 2 {
		t.Fatalf("exit 2: %s", errOut)
	}
	var fs []struct{ File, RuleID, Message string }
	if err := json.Unmarshal([]byte(out), &fs); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var lines []string
	for _, f := range fs {
		lines = append(lines, strings.TrimPrefix(strings.TrimPrefix(f.File, root), "/")+"|"+f.RuleID+"|"+f.Message)
	}
	sort.Strings(lines)
	return lines
}

// The Claude Code lists are checked against .claude/settings.json only. A
// .devin/config.json used to receive them too and report each entry a second
// time with no file name (#1081).
func TestPolicy_ClaudeListsOnlyOnSettings(t *testing.T) {
	root := runFixture(t, map[string]string{
		".cfgaudit.yml":         "policy:\n  require-deny: [\"Bash(git push:*)\"]\n",
		".claude/settings.json": `{"permissions":{"deny":["Read(.env)"]}}`,
		".devin/config.json":    `{"permissions":{"allow":["Exec(git status)"]}}`,
	})
	got := policyFindings(t, root)
	if len(got) != 1 || !strings.HasPrefix(got[0], ".claude/settings.json|CFG025|") {
		t.Fatalf("got %q", got)
	}
}

// Without policy.agents the neutral policy reaches every agent with
// configuration in the repository, and no other.
func TestPolicy_NeutralDefaultAgents(t *testing.T) {
	root := runFixture(t, map[string]string{
		".cfgaudit.yml":         "policy:\n  deny:\n    commands: [\"git push\"]\n",
		".claude/settings.json": `{"permissions":{"deny":["Bash(git:*)"]}}`,
		".devin/config.json":    `{"mcpServers":{}}`,
		".zed/tasks.json":       `[]`,
	})
	got := policyFindings(t, root)
	want := []string{
		`.devin/config.json|CFG025|policy deny.commands "git push": no permissions.deny entry covers it, so Devin CLI does not block it; add "Exec(git push)"`,
		`.zed|CFG118|policy deny.commands cannot be enforced for Zed from the repository: Zed reads its permission rules from user settings only, so each contributor has to add the rules to their own settings`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// No agent configuration at all: nothing to check.
	root = runFixture(t, map[string]string{".cfgaudit.yml": "policy:\n  deny:\n    commands: [\"git push\"]\n"})
	if got := policyFindings(t, root); len(got) != 0 {
		t.Fatalf("got %q", got)
	}
}

// An agent named under policy.agents is checked even without configuration,
// against the file the deny belongs in, and an agent not named is left out.
func TestPolicy_NeutralListedAgents(t *testing.T) {
	root := runFixture(t, map[string]string{
		".cfgaudit.yml":   "policy:\n  deny:\n    commands: [\"git push\"]\n  agents: [claude-code, devin, continue]\n",
		".zed/tasks.json": `[]`,
	})
	got := policyFindings(t, root)
	want := []string{
		`.claude/settings.json|CFG025|policy deny.commands "git push": no permissions.deny entry covers it, so Claude Code does not block it; add "Bash(git push *)"`,
		`.continue|CFG118|policy deny.commands cannot be enforced for Continue from the repository: Continue reads its permission rules from user settings only, so each contributor has to add the rules to their own settings`,
		`.devin/config.json|CFG025|policy deny.commands "git push": no permissions.deny entry covers it, so Devin CLI does not block it; add "Exec(git push)"`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// The targets attachPolicy adds for an agent without configuration carry no
// configuration, so no other rule reports anything on them.
func TestPolicy_AddedTargetsAreQuiet(t *testing.T) {
	root := runFixture(t, map[string]string{
		".cfgaudit.yml": "policy:\n  deny:\n    commands: [\"git push\"]\n  agents: [claude-code, devin, zed]\n",
	})
	code, out, errOut := runCLI(t, "--claude-version", "2.1.316", "--skip", "CFG025,CFG118", "--format", "json", root)
	if code != 0 || strings.TrimSpace(out) != "[]" {
		t.Fatalf("exit %d, findings %s\n%s", code, out, errOut)
	}
}

// An agent the policy cannot check yet is a config error, exit 2.
func TestPolicy_UnknownAgentExit2(t *testing.T) {
	root := runFixture(t, map[string]string{".cfgaudit.yml": "policy:\n  agents: [cursor]\n"})
	code, _, errOut := runCLI(t, "--claude-version", "2.1.316", root)
	if code != 2 || !strings.Contains(errOut, `policy.agents: "cursor" is not an agent the policy can check yet`) {
		t.Fatalf("exit %d: %s", code, errOut)
	}
}
