package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func agentHooksTarget(kind string, hooks map[string][]parser.AgentHook, disableAll bool) *Target {
	return &Target{
		Scope:          finding.ScopeProject,
		AgentHooks:     &parser.AgentHooks{Version: 1, DisableAllHooks: disableAll, Hooks: hooks},
		AgentHooksFile: ".cursor/hooks.json",
		AgentHooksKind: kind,
	}
}

func TestCFG086_ZeroClickEvents(t *testing.T) {
	for _, event := range []string{"workspaceOpen", "sessionStart"} {
		tgt := agentHooksTarget("Cursor", map[string][]parser.AgentHook{
			event: {{Command: "./setup.sh"}},
		}, false)
		f := CFG086.Check(tgt)
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("expected 1 Error for %s, got %+v", event, f)
		}
	}
}

// Copilot accepts a camelCase and a PascalCase spelling of every event, so a
// matcher keyed to one would miss files written with the other.
func TestCFG086_EventSpellingAliases(t *testing.T) {
	for _, event := range []string{"SessionStart", "sessionStart", "WorkspaceOpen", "workspaceopen"} {
		tgt := agentHooksTarget("Copilot", map[string][]parser.AgentHook{
			event: {{Type: "command", Bash: "./x.sh"}},
		}, false)
		if f := CFG086.Check(tgt); len(f) != 1 {
			t.Errorf("expected the finding for spelling %q, got %+v", event, f)
		}
	}
}

// Copilot's per-platform command fields must both be seen.
func TestCFG086_CopilotCommandFields(t *testing.T) {
	for _, h := range []parser.AgentHook{
		{Type: "command", Bash: "./x.sh"},
		{Type: "command", Shell: "./x.ps1"},
		{Type: "command", Command: "./x"},
	} {
		tgt := agentHooksTarget("Copilot", map[string][]parser.AgentHook{"SessionStart": {h}}, false)
		if f := CFG086.Check(tgt); len(f) != 1 {
			t.Errorf("expected the finding for hook %+v, got %+v", h, f)
		}
	}
}

// Events that need an explicit user action are not this rule's concern; the
// command content is judged by the command-content rules regardless.
func TestCFG086_ExplicitActionEvents_NoFinding(t *testing.T) {
	for _, event := range []string{"preToolUse", "postToolUse", "beforeShellExecution", "userPromptSubmitted", "stop"} {
		tgt := agentHooksTarget("Cursor", map[string][]parser.AgentHook{event: {{Command: "./x.sh"}}}, false)
		if f := CFG086.Check(tgt); len(f) != 0 {
			t.Errorf("expected no finding for %s, got %+v", event, f)
		}
	}
}

// A prompt or http hook runs no shell command, so there is nothing to execute
// on folder open.
func TestCFG086_NonCommandHooks_NoFinding(t *testing.T) {
	for _, h := range []parser.AgentHook{
		{Type: "prompt"},
		{Type: "http", URL: "https://example.com/hook"},
	} {
		tgt := agentHooksTarget("Cursor", map[string][]parser.AgentHook{"workspaceOpen": {h}}, false)
		if f := CFG086.Check(tgt); len(f) != 0 {
			t.Errorf("expected no finding for %+v, got %+v", h, f)
		}
	}
}

// disableAllHooks turns the whole Copilot file off, so nothing in it runs.
func TestCFG086_DisableAllHooks_NoFinding(t *testing.T) {
	tgt := agentHooksTarget("Copilot", map[string][]parser.AgentHook{
		"SessionStart": {{Type: "command", Bash: "./x.sh"}},
	}, true)
	if f := CFG086.Check(tgt); len(f) != 0 {
		t.Errorf("expected no finding when disableAllHooks is set, got %+v", f)
	}
}

func TestCFG086_NoHooks_NoFinding(t *testing.T) {
	if f := CFG086.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding without hooks, got %+v", f)
	}
}
