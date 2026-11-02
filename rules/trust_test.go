// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/parser"
)

// TrustEntries lists what runs, loads or is approved, and not the prose
// (#999).
func TestTrustEntries999(t *testing.T) {
	s := &parser.Settings{
		Permissions: &parser.Permissions{Allow: []string{"Bash(npm test)", "Bash(git status)"}, AdditionalDirectories: []string{"~"}, DefaultMode: "acceptEdits"},
		Hooks:       map[string][]parser.HookGroup{"SessionStart": {{Hooks: []parser.HookCommand{{Type: "command", Command: "./x.sh"}}}}},
		MCPServers:  map[string]parser.MCPServer{"remote": {URL: "https://example.invalid/mcp"}},
		Raw:         map[string]json.RawMessage{"enabledPlugins": json.RawMessage(`{ "a@b" : true }`)},
	}
	vs := &parser.VSCodeSettings{Raw: map[string]json.RawMessage{"chat.tools.autoApprove": json.RawMessage("true"), "editor.tabSize": json.RawMessage("2")}}
	tg := &Target{
		SettingsFile: "s.json", Settings: s,
		ProjectMCPFile: ".mcp.json", ProjectMCP: map[string]parser.MCPServer{"local": {Command: "npx", Args: []string{"-y", "srv@1.0.0"}}},
		VSCodeSettingsFile: ".vscode/settings.json", VSCodeSettings: vs,
		InstructionFile: "CLAUDE.md", InstructionContent: "prose",
		LaunchedScripts: []LaunchedScript{{File: "x.sh", Label: "script x.sh, started by the hooks.SessionStart command,", Content: "echo hi\n"}},
	}
	var got []string
	for _, e := range TrustEntries(tg) {
		got = append(got, e.Kind+"|"+e.File+"|"+e.Name+"|"+e.Value)
	}
	all := strings.Join(got, "\n")
	for _, want := range []string{
		"command|s.json|hooks.SessionStart command|./x.sh",
		"command|.mcp.json|mcpServers.local command|npx -y srv@1.0.0",
		"mcp|.mcp.json|local|npx -y srv@1.0.0",
		"mcp|s.json|remote|https://example.invalid/mcp",
		"script|x.sh|started by the hooks.SessionStart command|",
		"instructions|CLAUDE.md|instructions|",
		"setting|s.json|permissions.allow|Bash(npm test)",
		"setting|s.json|permissions.additionalDirectories|~",
		"setting|s.json|permissions.defaultMode|acceptEdits",
		`setting|s.json|enabledPlugins|{"a@b":true}`,
		"setting|.vscode/settings.json|chat.tools.autoApprove|true",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in\n%s", want, all)
		}
	}
	if strings.Contains(all, "editor.tabSize") || strings.Contains(all, "prose") {
		t.Errorf("unexpected entry in\n%s", all)
	}
	if TrustEntries(nil) != nil {
		t.Error("nil target")
	}
	if compactJSON(json.RawMessage("{bad")) != "{bad" {
		t.Error("invalid JSON should come back as written")
	}
}

func TestMCPInventory1000(t *testing.T) {
	tg := &Target{
		SettingsFile: "b.json", Settings: &parser.Settings{MCPServers: map[string]parser.MCPServer{"z": {URL: "https://x.invalid", Type: "sse"}}},
		ProjectMCPFile: "a.json", ProjectMCP: map[string]parser.MCPServer{
			"pinned": {Command: "npx", Args: []string{"-y", "p@1.0.0"}},
			"loose":  {Command: "/usr/bin/uvx", Args: []string{"srv"}},
			"node":   {Command: "node", Args: []string{"s.js"}},
			"http":   {URL: "https://y.invalid"},
		},
	}
	var got []string
	for _, m := range MCPInventory(tg) {
		got = append(got, m.File+"|"+m.Name+"|"+m.Transport+"|"+m.Pinned)
	}
	if want := "a.json|http|http|,a.json|loose|stdio|no,a.json|node|stdio|,a.json|pinned|stdio|yes,b.json|z|sse|"; strings.Join(got, ",") != want {
		t.Errorf("got %v", got)
	}
	if MCPInventory(nil) != nil {
		t.Error("nil target")
	}
}
