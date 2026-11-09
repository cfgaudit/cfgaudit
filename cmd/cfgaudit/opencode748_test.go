// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// An OpenCode 2 config with a permissions list loads in OpenCode 2, so its MCP
// servers and its rules are read (#748).
func TestOpenCode2Permissions(t *testing.T) {
	root := runFixture(t, map[string]string{
		"opencode.json": `{"permissions": [{"action": "read", "resource": "*", "effect": "allow"}],
		  "agents": {"rev": {"permissions": [{"action": "external_directory", "resource": "*", "effect": "allow"}]}},
		  "mcp": {"servers": {"a": ` + ocEvilServer + `}}}`,
		".opencode/agent/v2.md":  "---\nsystem: x\npermission:\n  read: allow\npermissions:\n  - action: external_directory\n    resource: \"~/**\"\n    effect: allow\n---\nbody\n",
		".opencode/agent/old.md": "---\ndescription: x\npermission:\n  read: allow\n---\nbody\n",
	})
	got := map[string]int{}
	var msgs []string
	for _, f := range scanFindings(t, "--only", "CFG019,CFG105", root) {
		rel, _ := filepath.Rel(root, f.File)
		got[f.RuleID+" "+filepath.ToSlash(rel)]++
		msgs = append(msgs, f.Message)
	}
	all := strings.Join(msgs, "\n")
	if got["CFG019 opencode.json"] != 1 || got["CFG105 opencode.json"] != 2 || got["CFG105 .opencode/agent/v2.md"] != 1 || got["CFG105 .opencode/agent/old.md"] != 1 {
		t.Fatalf("got %v\n%s", got, all)
	}
	for _, want := range []string{`permissions resolves reading *.env to "allow" (from {"action": "read", "resource": "*", "effect": "allow"})`, "agents.rev.permissions resolves external_directory", "agents.v2.permissions resolves external_directory", `add {"action": "read", "resource": "*.env", "effect": "ask"}`} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in\n%s", want, all)
		}
	}
	if strings.Contains(all, "agent.v2.permission resolves reading") {
		t.Errorf("the v1 block of a V2 agent file was read:\n%s", all)
	}
}

// Kilo Code rejects a file with a v2 permissions block, so its rules do not
// count for Kilo Code's policy check, while OpenCode's still reads them.
func TestOpenCode2PermissionsKilo(t *testing.T) {
	root := runFixture(t, map[string]string{
		".cfgaudit.yml": "policy:\n  deny:\n    commands: [\"git push\"]\n  agents: [opencode, kilo-code]\n",
		"opencode.json": `{"permissions": [{"action": "shell", "resource": "git push *", "effect": "deny"}]}`,
	})
	got := policyFindings(t, root)
	if len(got) != 1 || !strings.Contains(got[0], "Kilo Code does not block it") {
		t.Fatalf("got %q", got)
	}
}
