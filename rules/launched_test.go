// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"reflect"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func TestLaunchCommands(t *testing.T) {
	tg := settingsTarget(t, `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"node a.mjs"}]}]}}`)
	tg.VSCodeTasks = &parser.VSCodeTasks{Tasks: []parser.VSCodeTask{
		{Label: "open", Command: "bash b.sh", RunOptions: &parser.VSCodeRunOptions{RunOn: "folderOpen"}},
		{Label: "manual", Command: "bash c.sh"},
	}}
	tg.VSCodeTasksFile = ".vscode/tasks.json"
	tg.ProjectMCP = map[string]parser.MCPServer{"srv": {Command: "python", Args: []string{"d.py"}}}
	tg.ProjectMCPFile = ".mcp.json"
	var got []string
	for _, lc := range LaunchCommands(tg) {
		got = append(got, lc.Label+" | "+lc.File+" | "+lc.Command)
	}
	want := []string{
		"hooks.SessionStart command | test/settings.json | node a.mjs",
		`VS Code folderOpen task "open" command | .vscode/tasks.json | bash b.sh`,
		"mcpServers.srv command | .mcp.json | python d.py",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
	if LaunchCommands(nil) != nil {
		t.Error("nil target")
	}
}

// Shell scripts become one site per non-comment line; other files and files
// reached through another script are left to CFG119.
func TestCommandSitesWithScripts(t *testing.T) {
	tg := &Target{LaunchedScripts: []LaunchedScript{
		{Label: "script s.sh,", File: "s.sh", Content: "#!/bin/sh\n# comment\n\necho a\necho b\n"},
		{Label: "script j.js,", File: "j.js", Content: "console.log(1)"},
		{Label: "file p.sh,", File: "p.sh", Content: "echo c", Via: "j.js"},
	}}
	var got []string
	for _, s := range commandSitesWithScripts(tg) {
		got = append(got, s.File+": "+s.Command)
	}
	if want := []string{"s.sh: echo a", "s.sh: echo b"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	if commandSitesWithScripts(nil) != nil {
		t.Error("nil target")
	}
	if n := toolsOf([]string{".mcp.json", ".claude/settings.json", ".claude/settings.local.json"}); n != 2 {
		t.Errorf("toolsOf = %d, want 2", n)
	}
}
