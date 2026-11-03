// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func TestCFG125_VerifiedBypassFormsInAutoRunHook(t *testing.T) {
	commands := []string{
		"claude --dangerously-skip-permissions -p x",
		"claude --permission-mode bypassPermissions -p x",
		"codex --dangerously-bypass-approvals-and-sandbox exec x",
		"codex --yolo exec x",
		"codex --full-auto exec x",
		"codex -s danger-full-access exec x",
		"gemini --yolo -p x", "gemini -y -p x",
		"qwen --yolo -p x", "qwen -y -p x",
		"cursor-agent --force -p x", "agent -f -p x",
	}
	for _, command := range commands {
		target := settingsTarget(t, `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"`+command+`"}]}]}}`)
		f := CFG125.Check(target)
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("%s: expected one Error, got %+v", command, f)
		}
	}
}

func TestCFG125_WrappersChainsQuotesAndWindows(t *testing.T) {
	commands := []string{
		"cd sub && claude --dangerously-skip-permissions -p x",
		"npx @anthropic-ai/claude-code --dangerously-skip-permissions -p x",
		"env -u TOKEN X=1 codex --yolo exec x",
		`"C:\\Tools\\cursor-agent.exe" --force -p x`,
		`'/usr/local/bin/gemini' -y -p x`,
	}
	for _, command := range commands {
		target := settingsTarget(t, `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"`+stringsForJSON(command)+`"}]}]}}`)
		if f := CFG125.Check(target); len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("%s: expected one Error, got %+v", command, f)
		}
	}
}

func TestCFG125_UserTriggeredTaskAndSkillScriptAreWarn(t *testing.T) {
	task := &Target{
		VSCodeTasksFile: ".vscode/tasks.json",
		VSCodeTasks:     &parser.VSCodeTasks{Tasks: []parser.VSCodeTask{{Label: "agent", Command: "codex --yolo exec x"}}},
	}
	if f := CFG125.Check(task); len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("plain VS Code task: expected Warn, got %+v", f)
	}
	skill := &Target{LaunchedScripts: []LaunchedScript{{
		Label: "script run.sh, shipped with the skill skills/x/SKILL.md,", File: "skills/x/run.sh",
		Content: "#!/bin/sh\nclaude --dangerously-skip-permissions -p x\n", Skill: "skills/x/SKILL.md",
	}}}
	f := CFG125.Check(skill)
	if len(f) != 1 || f[0].Severity != finding.Warn || f[0].Line != 2 {
		t.Fatalf("skill script: expected line-attributed Warn, got %+v", f)
	}
}

func TestCFG125_FolderOpenTaskAndMCPAreErrors(t *testing.T) {
	target := &Target{
		VSCodeTasksFile: ".vscode/tasks.json",
		VSCodeTasks: &parser.VSCodeTasks{Tasks: []parser.VSCodeTask{{
			Label: "agent", Command: "gemini",
			RunOptions: &parser.VSCodeRunOptions{RunOn: "folderOpen"},
		}}},
		ProjectMCPFile: ".mcp.json",
		ProjectMCP:     map[string]parser.MCPServer{"agent": {Command: "codex", Args: []string{"--yolo", "exec", "x"}}},
	}
	// Set the task command as a single shell string because its typed Args use
	// raw JSON values and are covered separately by parser end-to-end tests.
	target.VSCodeTasks.Tasks[0].Command = "gemini -y -p x"
	f := CFG125.Check(target)
	if len(f) != 2 {
		t.Fatalf("expected task and MCP errors, got %+v", f)
	}
	for _, got := range f {
		if got.Severity != finding.Error {
			t.Errorf("expected Error, got %+v", got)
		}
	}
}

func TestCFG125_FlagNeedsMatchingAgent(t *testing.T) {
	for _, command := range []string{"echo --yolo", "node wrapper.js codex --yolo", "claude --version", "codex exec x", "other --force"} {
		target := settingsTarget(t, `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"`+command+`"}]}]}}`)
		if f := CFG125.Check(target); len(f) != 0 {
			t.Errorf("%s: expected no finding, got %+v", command, f)
		}
	}
}

func stringsForJSON(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, `"`, `\"`)
}

func TestCFG125_ScriptMessageDoesNotExecuteQuotedAgentCommand(t *testing.T) {
	target := &Target{LaunchedScripts: []LaunchedScript{{
		Label: "script check.sh, started by a hook,", File: "check.sh",
		Content: `echo "claude --dangerously-skip-permissions -p x"` + "\n",
	}}}
	if f := CFG125.Check(target); len(f) != 0 {
		t.Errorf("printed command example must not be treated as execution: %+v", f)
	}
}
