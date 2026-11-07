// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/config"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

// Roo Code, Gemini CLI and pi keep what they can in the repository, and CFG118
// names the rest (#1517).
func TestPolicy_RooGeminiPi(t *testing.T) {
	policy := "policy:\n  deny:\n    commands: [\"git push\"]\n    read: [\"**/.env\"]\n    fetch: [\"example.com\"]\n    mcp-tools: [\"gh:delete_repo\"]\n"
	root := runFixture(t, map[string]string{
		".cfgaudit.yml":         policy,
		".roorules":             "rules\n",
		".rooignore":            ".env\n",
		".roo/mcp.json":         `{"mcpServers":{"gh":{"command":"x","disabledTools":["delete_repo"]}}}`,
		".vscode/settings.json": `{"roo-cline.deniedCommands":["git push"]}`,
	})
	got := policyFindings(t, root)
	if len(got) != 1 || !strings.HasPrefix(got[0], ".roo|CFG118|policy deny.fetch cannot be enforced for Roo Code") {
		t.Fatalf("got %q", got)
	}

	root = runFixture(t, map[string]string{
		".cfgaudit.yml":         policy,
		"GEMINI.md":             "notes\n",
		".gemini/settings.json": `{"tools":{"exclude":["run_shell_command","web_fetch"]},"mcp":{"excluded":["gh"]}}`,
	})
	got = policyFindings(t, root)
	if len(got) != 1 || !strings.Contains(got[0], "policy deny.read cannot be enforced for Gemini CLI") {
		t.Fatalf("got %q", got)
	}

	// Everything off leaves nothing to report.
	root = runFixture(t, map[string]string{
		".cfgaudit.yml":         "policy:\n  deny:\n    commands: [\"git push\"]\n  agents: [gemini-cli]\n",
		".gemini/settings.json": `{"tools":{"core":["read_file"]},"mcp":{"excluded":["*"]}}`,
	})
	got = policyFindings(t, root)
	if len(got) != 0 {
		t.Fatalf("got %q", got)
	}

	for settings, want := range map[string]string{
		`{"defaultTools":["read","edit"]}`: "policy deny.read, deny.write",
		`{"defaultTools":["-bash"]}`:       "policy deny.read",
		`{"defaultTools":"bash"}`:          "policy deny.commands",
		`{"theme":"dark"}`:                 "policy deny.commands",
	} {
		root = runFixture(t, map[string]string{
			".cfgaudit.yml":     "policy:\n  deny:\n    commands: [\"git push\"]\n    read: [\"**/.env\"]\n    write: [\"src/**\"]\n",
			".pi/settings.json": settings,
		})
		got = policyFindings(t, root)
		if len(got) != 1 || !strings.Contains(got[0], want) {
			t.Errorf("%s: got %q", settings, got)
		}
	}
}

func TestPolicyToolHelpers(t *testing.T) {
	// A home path goes to CFG118 for Roo Code, by category.
	got := rooUnenforced(config.PolicyRules{Read: []string{"~/.ssh/**"}, Write: []string{"~/.aws/**"}})
	if strings.Join(got, ",") != "fetch,read,write" {
		t.Errorf("got %q", got)
	}
	if got := rooUnenforced(config.PolicyRules{Read: []string{"**/.env"}}); len(got) != 1 {
		t.Errorf("got %q", got)
	}
	off := map[string]bool{"commands": true, "read": true, "write": true, "fetch": true, "mcp-tools": true}
	if got := toolSwitchAgent("pi", "pi", "p", off, "r"); got != nil {
		t.Errorf("all off: got %+v", got)
	}
	s := &parser.GeminiSettings{MCP: json.RawMessage(`{"excluded":["gh"]}`)}
	if got := geminiToolsOff(s, config.PolicyRules{MCPTools: []string{"gh:x"}}); !got["mcp-tools"] {
		t.Errorf("got %+v", got)
	}
	if got := geminiToolsOff(s, config.PolicyRules{MCPTools: []string{"other:x"}}); got["mcp-tools"] {
		t.Errorf("got %+v", got)
	}
}

// A settings value of another shape reads as no list.
func TestPolicy_RooWrongShape(t *testing.T) {
	root := runFixture(t, map[string]string{
		".cfgaudit.yml":         "policy:\n  deny:\n    commands: [\"git push\"]\n",
		".rooignore":            ".env\n",
		".vscode/settings.json": `{"roo-cline.deniedCommands":"git push"}`,
	})
	got := policyFindings(t, root)
	if len(got) != 1 || !strings.HasPrefix(got[0], ".vscode/settings.json|CFG025|") {
		t.Fatalf("got %q", got)
	}
}
