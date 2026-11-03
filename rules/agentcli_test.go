// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"slices"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

// Every verified bypass form in the CLI table on #1420 reaches agentBypass,
// in its two-word and its flag=value spelling where it takes a value.
func TestAgentBypass_VerifiedFormsPerAgent(t *testing.T) {
	for _, command := range []string{
		"claude --permission-mode=bypassPermissions -p x",
		"codex --sandbox danger-full-access exec x",
		"codex --sandbox=danger-full-access exec x",
		"codex -a never exec x",
		"codex --ask-for-approval=never exec x",
		"gemini --approval-mode=yolo -p x",
		"qwen --approval-mode yolo -p x",
		"cursor-agent --approve-mcps -p x",
		"cursor-agent --sandbox disabled -p x",
		"opencode run --auto x",
		"kilo run --dangerously-skip-permissions x",
		"kimi --print -p x",
		"kimi --afk",
		"copilot --allow-all-tools -p x",
		"copilot --no-sandbox -p x",
		"devin --permission-mode dangerous -p x",
		"devin --permission-mode=yolo -p x",
		"goose run -t x",
		"cline -y x",
		"crush run x",
		"crush --yolo",
		"aider --yes-always -m x",
		"droid --skip-permissions-unsafe",
		"droid exec --auto high x",
		"q chat --no-interactive --trust-all-tools x",
		"kiro-cli chat --trust-all-tools --no-interactive x",
	} {
		invs := agentInvocations(command)
		if len(invs) != 1 {
			t.Fatalf("%s: expected one invocation, got %+v", command, invs)
		}
		if _, ok := agentBypass(invs[0]); !ok {
			t.Errorf("%s: expected a bypass", command)
		}
	}
}

func TestAgentBypass_SafeFormsPerAgent(t *testing.T) {
	for _, command := range []string{
		"codex -a on-request exec x",
		"codex --sandbox workspace-write exec x",
		"gemini --approval-mode=default -p x",
		"cursor-agent --sandbox enabled -p x",
		"devin --permission-mode smart -p x",
		"goose session",
		"crush",
		"aider -m x",
		"droid exec --auto low x",
		"q chat --trust-all-tools x",
		"kiro-cli chat --no-interactive x",
		"q translate x",
		"junie x",
	} {
		for _, inv := range agentInvocations(command) {
			if flag, ok := agentBypass(inv); ok {
				t.Errorf("%s: unexpected bypass %q", command, flag)
			}
		}
	}
}

func TestCFG023_AgentCLIReadOnlyFormsPerAgent(t *testing.T) {
	for _, entry := range []string{
		"Bash(claude doctor:*)", "Bash(claude auth status)", "Bash(claude mcp get *)",
		"Bash(codex login status:*)", "Bash(codex mcp list:*)", "Bash(codex --help:*)",
		"Bash(gemini extensions list:*)", "Bash(qwen status:*)", "Bash(devin auth status:*)",
		"Bash(opencode models:*)", "Bash(kilo mcp list:*)", "Bash(goose info:*)", "Bash(goose doctor:*)",
	} {
		if f := CFG023.Check(settingsTarget(t, `{"permissions":{"allow":["`+entry+`"]}}`)); len(f) != 0 {
			t.Errorf("%s: expected no finding, got %+v", entry, f)
		}
	}
	// A read-only word for one CLI is not read-only for another.
	if f := CFG023.Check(settingsTarget(t, `{"permissions":{"allow":["Bash(goose models:*)"]}}`)); len(f) != 1 {
		t.Errorf("goose models: expected a finding, got %+v", f)
	}
}

func TestAgentInvocationFields_RunnerEdges(t *testing.T) {
	for _, fields := range [][]string{
		{"npx", "-y"},
		{"npx", "-p", "x"},
		{"env", "-u", "TOKEN"},
		{"X=1"},
	} {
		if inv, ok := agentInvocationFields(fields); ok {
			t.Errorf("%v: expected no invocation, got %+v", fields, inv)
		}
	}
	inv, ok := agentInvocationFields([]string{"command", "bunx", "--package", "x", "@openai/codex", "--yolo"})
	if !ok || inv.agent != "codex" || !slices.Equal(inv.args, []string{"--yolo"}) {
		t.Errorf("bunx --package: got %+v, %v", inv, ok)
	}
}

func TestIsShellAssignment(t *testing.T) {
	for word, want := range map[string]bool{
		"A_1=x": true, "_X=": true,
		"-X=1": false, "=v": false, "1A=x": false, "A-B=x": false, "plain": false,
	} {
		if got := isShellAssignment(word); got != want {
			t.Errorf("isShellAssignment(%q) = %v, want %v", word, got, want)
		}
	}
}

func TestHasAgentConfigDeny_Forms(t *testing.T) {
	tests := []struct {
		deny []string
		want bool
	}{
		{[]string{"Write"}, true},
		{[]string{"Edit(./.codex/**)"}, true},
		{[]string{"Edit(settings.json)"}, true},
		{[]string{"Edit(/)", "Edit(./)"}, false},
		{[]string{"Edit(src/**)", "Write(.codex/config.toml)", "Read(.mcp.json)"}, false},
	}
	for _, tt := range tests {
		if got := hasAgentConfigDeny(tt.deny); got != tt.want {
			t.Errorf("hasAgentConfigDeny(%v) = %v, want %v", tt.deny, got, tt.want)
		}
	}
}

func TestAgentSubcommandArgs(t *testing.T) {
	takes := map[string]bool{"-c": true}
	if got := agentSubcommandArgs([]string{"-c", "x", "--", "mcp-server"}, takes); !slices.Equal(got, []string{"mcp-server"}) {
		t.Errorf("after --: got %v", got)
	}
	if got := agentSubcommandArgs([]string{"-c=x", "app-server"}, takes); !slices.Equal(got, []string{"app-server"}) {
		t.Errorf("-c=x: got %v", got)
	}
	if got := agentSubcommandArgs([]string{"--debug", "-c", "x"}, takes); got != nil {
		t.Errorf("only options: got %v", got)
	}
}

func TestAgentRules_NilTarget(t *testing.T) {
	for _, r := range []Rule{CFG023, CFG124, CFG125} {
		if f := r.Check(nil); f != nil {
			t.Errorf("%s: nil target gave %+v", r.ID(), f)
		}
	}
}

// Sites a user or the model has to trigger are warn: a skill `!` command, a
// subagent frontmatter hook and a value a hook passes to a tool.
func TestCFG125_UserTriggeredCommandSitesAreWarn(t *testing.T) {
	targets := map[string]*Target{
		"skill command": {
			InstructionFile:    ".claude/skills/x/SKILL.md",
			SkillShellCommands: []string{"claude --dangerously-skip-permissions -p x"},
		},
		"frontmatter hook": {
			SubagentHooksFile: ".claude/agents/a.md",
			SubagentHooks: map[string][]parser.HookGroup{"PreToolUse": {{
				Hooks: []parser.HookCommand{{Type: "command", Command: "codex --yolo exec x"}},
			}}},
		},
		"hook input": {
			CodexHooksFile: ".codex/hooks.json",
			CodexHooks: &parser.CodexHooks{Events: map[string][]parser.CodexMatcherGroup{
				"PreToolUse": {{Hooks: []parser.CodexHookHandler{{
					Type: "mcp_tool", Server: "shell", Tool: "run",
					Input: map[string]any{"command": "gemini -y -p x"},
				}}}},
			}},
		},
	}
	for name, target := range targets {
		f := CFG125.Check(target)
		if len(f) != 1 || f[0].Severity != finding.Warn {
			t.Errorf("%s: expected one Warn, got %+v", name, f)
		}
	}
}

// A command reached twice through the same site is reported once.
func TestCFG125_DuplicateSiteReportedOnce(t *testing.T) {
	target := &Target{
		InstructionFile:    ".claude/skills/x/SKILL.md",
		SkillShellCommands: []string{"codex --yolo exec x", "codex --yolo exec x"},
	}
	if f := CFG125.Check(target); len(f) != 1 {
		t.Errorf("expected one finding, got %+v", f)
	}
}
