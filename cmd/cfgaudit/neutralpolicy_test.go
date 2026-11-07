// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// policyFindings scans root with only the policy rules and returns
// "file|rule|message" lines, sorted, with the file relative to root in
// forward slashes.
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
		rel, err := filepath.Rel(root, f.File)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, filepath.ToSlash(rel)+"|"+f.RuleID+"|"+f.Message)
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
		`.zed|CFG118|policy deny.commands cannot be enforced for Zed from a permission file in the repository: Zed reads its permission rules from user settings only, so each contributor has to add the rules to their own settings`,
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
		`.continue|CFG118|policy deny.commands cannot be enforced for Continue from a permission file in the repository: Continue reads its permission rules from user settings only, so each contributor has to add the rules to their own settings`,
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

// goose, Kimi CLI and Cline have no committed permission file. Each is found
// by its markers, and Cline's finding names the hook instead of user settings.
func TestPolicy_AgentsWithoutPermissionFile(t *testing.T) {
	root := runFixture(t, map[string]string{
		".cfgaudit.yml":        "policy:\n  deny:\n    commands: [\"git push\"]\n",
		".goosehints":          "hints\n",
		".kimi/AGENTS.md":      "notes\n",
		".clinerules/style.md": "rules\n",
	})
	got := policyFindings(t, root)
	want := []string{".clinerules|CFG118|", ".goosehints|CFG118|", ".kimi|CFG118|"}
	if len(got) != len(want) {
		t.Fatalf("got %q", got)
	}
	for i, prefix := range want {
		if !strings.HasPrefix(got[i], prefix) {
			t.Errorf("finding %d: got %q, want prefix %q", i, got[i], prefix)
		}
	}
	if !strings.Contains(got[0], "only a PreToolUse hook committed under .cline/hooks") {
		t.Errorf("Cline reason: %q", got[0])
	}
	if !strings.Contains(got[1], "goose reads its permission rules from user settings only") {
		t.Errorf("goose reason: %q", got[1])
	}
}

// A listed agent with no marker in the repository is reported at its first
// marker, which is what a team wants to see when it names the agent up front.
func TestPolicy_ListedAgentWithoutMarker(t *testing.T) {
	root := runFixture(t, map[string]string{
		".cfgaudit.yml": "policy:\n  deny:\n    read: [\"**/.env\"]\n  agents: [goose]\n",
	})
	got := policyFindings(t, root)
	if len(got) != 1 || !strings.HasPrefix(got[0], ".goose|CFG118|") {
		t.Fatalf("got %q", got)
	}
}

// Cursor CLI is in scope through .cursor/cli.json alone, takes denies from
// .claude/settings.json, and has its fetch entries reported by CFG118.
func TestPolicy_CursorCLI(t *testing.T) {
	root := runFixture(t, map[string]string{
		".cfgaudit.yml":         "policy:\n  deny:\n    commands: [\"git push\"]\n    read: [\"**/.env\"]\n    fetch: [\"example.com\"]\n",
		".claude/settings.json": `{"permissions":{"deny":["Bash(git)","Bash(git:*)","Read(**/.env)","WebFetch(domain:example.com)"]}}`,
		".cursor/cli.json":      `{"permissions":{"deny":[]}}`,
	})
	got := policyFindings(t, root)
	if len(got) != 1 || !strings.HasPrefix(got[0], ".cursor/cli.json|CFG118|policy deny.fetch cannot be enforced for Cursor CLI") {
		t.Fatalf("got %q", got)
	}

	// Only the CLI's own file marks it; .cursor/ alone may be the editor.
	root = runFixture(t, map[string]string{
		".cfgaudit.yml":          "policy:\n  deny:\n    commands: [\"git push\"]\n",
		".cursor/rules/style.md": "rules\n",
	})
	if got := policyFindings(t, root); len(got) != 0 {
		t.Fatalf("got %q", got)
	}

	// Named without a file: the missing deny is reported, and nothing else.
	root = runFixture(t, map[string]string{
		".cfgaudit.yml": "policy:\n  deny:\n    commands: [\"git push\"]\n  agents: [cursor-cli]\n",
	})
	got = policyFindings(t, root)
	want := `.cursor/cli.json|CFG025|policy deny.commands "git push": no permissions.deny entry covers it, so Cursor CLI does not block it; add "Shell(git push)"`
	if len(got) != 1 || got[0] != want {
		t.Fatalf("got %q", got)
	}
	code, out, _ := runCLI(t, "--claude-version", "2.1.316", "--format", "json", root)
	if code == 2 || strings.Count(out, `"rule_id"`) > 1 || strings.Count(out, `"RuleID"`) > 1 {
		t.Fatalf("exit %d, other rules fired:\n%s", code, out)
	}
}

// Qwen Code and Grok are found through their files, a [permission] table alone
// gives Grok a target, and Grok takes rules from .claude/settings.json.
func TestPolicy_QwenGrok(t *testing.T) {
	root := runFixture(t, map[string]string{
		".cfgaudit.yml":         "policy:\n  deny:\n    commands: [\"git push\"]\n",
		".claude/settings.json": `{"permissions":{"deny":["Bash(git:*)"]}}`,
		".grok/config.toml":     "[permission]\nallow = [\"Read\"]\n",
		".qwen/settings.json":   `{"permissions":{"deny":["Bash(git)"]}}`,
	})
	if got := policyFindings(t, root); len(got) != 0 {
		t.Fatalf("got %q", got)
	}

	root = runFixture(t, map[string]string{
		".cfgaudit.yml":     "policy:\n  deny:\n    read: [\"~/.ssh/**\"]\n",
		"QWEN.md":           "notes\n",
		".grok/config.toml": "[permission]\nrules = [{ action = \"deny\", tool = \"bash\", pattern = \"rm\" }]\n",
	})
	got := policyFindings(t, root)
	want := []string{
		`.grok/config.toml|CFG025|policy deny.read "~/.ssh/**": no permissions.deny entry covers it, so Grok does not block it; add "Read(**/.ssh/**)"`,
		`.qwen/settings.json|CFG025|policy deny.read "~/.ssh/**": no permissions.deny entry covers it, so Qwen Code does not block it; add "Read(~/.ssh/**)"`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// Named without a file: the missing deny is reported, and nothing else.
	root = runFixture(t, map[string]string{
		".cfgaudit.yml": "policy:\n  deny:\n    commands: [\"git push\"]\n  agents: [qwen-code, grok]\n",
	})
	if got := policyFindings(t, root); len(got) != 2 {
		t.Fatalf("got %q", got)
	}
	code, out, _ := runCLI(t, "--claude-version", "2.1.316", "--format", "json", root)
	if code == 2 || strings.Count(out, `"rule_id"`) > 2 {
		t.Fatalf("exit %d, other rules fired:\n%s", code, out)
	}
}

// OpenCode and Kilo Code read rules by the last match, across their files in
// order (#1515).
func TestPolicy_OpenCodeKilo(t *testing.T) {
	root := runFixture(t, map[string]string{
		".cfgaudit.yml":  "policy:\n  deny:\n    commands: [\"git push\"]\n    fetch: [\"example.com\"]\n",
		"opencode.json":  `{"permission":{"bash":{"git push *":"deny"}}}`,
		"opencode.jsonc": `{"permission":{"bash":{"git *":"allow"}}}`,
		"kilo.jsonc":     `{"permission":{"bash":{"git push *":"deny"},"webfetch":{"*://example.com/*":"deny"}}}`,
	})
	got := policyFindings(t, root)
	// Kilo Code reads opencode.jsonc after its own file, so that allow reopens
	// its deny too.
	want := []string{
		`opencode.jsonc|CFG025|policy deny.commands "git push": no rule denies it as the last match, so Kilo Code does not block it; add "git push *": "deny" under "bash" after the rules it has to override`,
		`opencode.jsonc|CFG025|policy deny.commands "git push": no rule denies it as the last match, so OpenCode does not block it; add "git push *": "deny" under "bash" after the rules it has to override`,
		`opencode.jsonc|CFG118|policy deny.fetch cannot be enforced for OpenCode from a permission file in the repository: OpenCode applies webfetch to every URL, so the only way to deny a domain is to turn the tool off`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got:\n%s", strings.Join(got, "\n"))
	}

	// Named without a file: the missing deny names the file to create.
	root = runFixture(t, map[string]string{
		".cfgaudit.yml": "policy:\n  deny:\n    read: [\"**/.env\"]\n  agents: [opencode, kilo-code]\n",
	})
	got = policyFindings(t, root)
	if len(got) != 2 || !strings.HasPrefix(got[0], "kilo.json|CFG025|") || !strings.HasPrefix(got[1], "opencode.json|CFG025|") {
		t.Fatalf("got %q", got)
	}

	// A whole-tool deny leaves nothing for CFG118, and .kilo marks Kilo Code.
	root = runFixture(t, map[string]string{
		".cfgaudit.yml":        "policy:\n  deny:\n    commands: [\"rm\"]\n    fetch: [\"example.com\"]\n",
		"opencode.json":        `{"permission":{"webfetch":"deny"}}`,
		".kilo/rules/style.md": "rules\n",
	})
	got = policyFindings(t, root)
	if len(got) != 2 || !strings.Contains(got[0], "Kilo Code does not block it") || !strings.Contains(got[1], "OpenCode does not block it") {
		t.Fatalf("got %q", got)
	}
}
