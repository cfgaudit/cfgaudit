package rules

import (
	"strings"
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

// #387: Grok .grok/hooks/*.json SessionStart is zero-click. CFG086 covers it via
// the shared GrokHooks path (the sessionstart entry), matching PascalCase and
// snake_case spellings.
func grokHooksTarget(hooks map[string][]parser.HookGroup) *Target {
	return &Target{
		Scope:         finding.ScopeProject,
		GrokHooks:     &parser.GrokHooks{Hooks: hooks},
		GrokHooksFile: ".grok/hooks/guard.json",
	}
}

func TestCFG086_Grok_SessionStart(t *testing.T) {
	for _, event := range []string{"SessionStart", "sessionStart", "session_start"} {
		tgt := grokHooksTarget(map[string][]parser.HookGroup{
			event: {{Hooks: []parser.HookCommand{{Type: "command", Command: "./setup.sh"}}}},
		})
		f := CFG086.Check(tgt)
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("expected 1 Error for Grok %q, got %+v", event, f)
		}
		if len(f) == 1 && !strings.Contains(f[0].Message, "Grok hooks.") {
			t.Errorf("expected the message to name the Grok file, got %q", f[0].Message)
		}
	}
}

func TestCFG086_Grok_ExplicitEvent_NoFinding(t *testing.T) {
	for _, event := range []string{"PreToolUse", "UserPromptSubmit", "PostToolUse"} {
		tgt := grokHooksTarget(map[string][]parser.HookGroup{
			event: {{Hooks: []parser.HookCommand{{Type: "command", Command: "./x.sh"}}}},
		})
		if f := CFG086.Check(tgt); len(f) != 0 {
			t.Errorf("expected no finding for explicit-action event %q, got %+v", event, f)
		}
	}
}

func TestCFG086_Grok_HTTPHook_NoFinding(t *testing.T) {
	// An http handler carries a url and no command, so it runs no shell command.
	tgt := grokHooksTarget(map[string][]parser.HookGroup{
		"SessionStart": {{Hooks: []parser.HookCommand{{Type: "http"}}}},
	})
	if f := CFG086.Check(tgt); len(f) != 0 {
		t.Errorf("expected no finding for an http hook, got %+v", f)
	}
}

// #389: Gemini .gemini/settings.json SessionStart is zero-click (startup/resume).
func geminiHooksTarget(gs *parser.GeminiSettings) *Target {
	return &Target{
		Scope:      finding.ScopeProject,
		Gemini:     gs,
		GeminiFile: ".gemini/settings.json",
	}
}

func TestCFG086_Gemini_SessionStart(t *testing.T) {
	tgt := geminiHooksTarget(&parser.GeminiSettings{
		Hooks: map[string][]parser.HookGroup{
			"SessionStart": {{Hooks: []parser.HookCommand{{Type: "command", Command: "./setup.sh"}}}},
		},
	})
	f := CFG086.Check(tgt)
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "Gemini hooks.SessionStart") {
		t.Errorf("expected the message to name the Gemini file, got %q", f[0].Message)
	}
}

// BeforeAgent fires only after a prompt is submitted (one-click), and BeforeTool
// needs an active turn — neither is zero-click.
func TestCFG086_Gemini_ExplicitEvent_NoFinding(t *testing.T) {
	for _, event := range []string{"BeforeAgent", "BeforeTool", "AfterModel", "SessionEnd"} {
		tgt := geminiHooksTarget(&parser.GeminiSettings{
			Hooks: map[string][]parser.HookGroup{
				event: {{Hooks: []parser.HookCommand{{Type: "command", Command: "./x.sh"}}}},
			},
		})
		if f := CFG086.Check(tgt); len(f) != 0 {
			t.Errorf("expected no finding for %q, got %+v", event, f)
		}
	}
}

// Gemini matches event names as exact PascalCase; a misspelled event is silently
// never run, so flagging it would be a false "this executes" claim.
func TestCFG086_Gemini_MisspelledEvent_NoFinding(t *testing.T) {
	for _, event := range []string{"sessionStart", "session_start", "sessionstart"} {
		tgt := geminiHooksTarget(&parser.GeminiSettings{
			Hooks: map[string][]parser.HookGroup{
				event: {{Hooks: []parser.HookCommand{{Type: "command", Command: "./x.sh"}}}},
			},
		})
		if f := CFG086.Check(tgt); len(f) != 0 {
			t.Errorf("expected no finding for non-PascalCase %q (Gemini never fires it), got %+v", event, f)
		}
	}
}

// hooksConfig.enabled: false disables the hook system, so nothing runs.
func TestCFG086_Gemini_HooksDisabled_NoFinding(t *testing.T) {
	off := false
	tgt := geminiHooksTarget(&parser.GeminiSettings{
		HooksConfig: &parser.GeminiHooksConfig{Enabled: &off},
		Hooks: map[string][]parser.HookGroup{
			"SessionStart": {{Hooks: []parser.HookCommand{{Type: "command", Command: "./x.sh"}}}},
		},
	})
	if f := CFG086.Check(tgt); len(f) != 0 {
		t.Errorf("expected no finding when hooksConfig.enabled is false, got %+v", f)
	}
}

// A SessionStart hook switched off by name in hooksConfig.disabled does not run.
func TestCFG086_Gemini_HookDisabledByName_NoFinding(t *testing.T) {
	tgt := geminiHooksTarget(&parser.GeminiSettings{
		HooksConfig: &parser.GeminiHooksConfig{Disabled: []string{"boot"}},
		Hooks: map[string][]parser.HookGroup{
			"SessionStart": {{Hooks: []parser.HookCommand{{Type: "command", Name: "boot", Command: "./x.sh"}}}},
		},
	})
	if f := CFG086.Check(tgt); len(f) != 0 {
		t.Errorf("expected no finding for a name-disabled hook, got %+v", f)
	}
}

// A runtime handler carries no shell command, so SessionStart with only a runtime
// hook is not flagged.
func TestCFG086_Gemini_RuntimeHook_NoFinding(t *testing.T) {
	tgt := geminiHooksTarget(&parser.GeminiSettings{
		Hooks: map[string][]parser.HookGroup{
			"SessionStart": {{Hooks: []parser.HookCommand{{Type: "runtime", Name: "x"}}}},
		},
	})
	if f := CFG086.Check(tgt); len(f) != 0 {
		t.Errorf("expected no finding for a runtime hook, got %+v", f)
	}
}
