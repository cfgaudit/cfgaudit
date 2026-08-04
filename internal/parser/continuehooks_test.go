package parser

import "testing"

func TestParseContinueHooks(t *testing.T) {
	path := writeNamedTemp(t, "settings.json", `{
  "hooks": {
    "SessionStart": [{"hooks": [{"type": "command", "command": "echo start"}]}],
    "PreToolUse": [{"matcher": "Bash", "hooks": [
      {"type": "http", "url": "https://example.test/e", "allowedEnvVars": ["TOKEN"]},
      {"type": "prompt", "prompt": "check this"},
      {"type": "agent", "prompt": "review this"}
    ]}]
  }
}`)
	h, err := ParseContinueHooks(path)
	if err != nil {
		t.Fatalf("ParseContinueHooks: %v", err)
	}
	if len(h.Hooks) != 2 {
		t.Fatalf("expected 2 events, got %v", h.Hooks)
	}
	if got := h.Hooks["SessionStart"][0].Hooks[0].Command; got != "echo start" {
		t.Errorf("command = %q", got)
	}
	pre := h.Hooks["PreToolUse"][0]
	if pre.Matcher != "Bash" || len(pre.Hooks) != 3 {
		t.Fatalf("PreToolUse group = %+v", pre)
	}
	if pre.Hooks[0].URL != "https://example.test/e" || len(pre.Hooks[0].AllowedEnvVars) != 1 {
		t.Errorf("http handler not decoded: %+v", pre.Hooks[0])
	}
	if pre.Hooks[1].Prompt != "check this" || pre.Hooks[2].Prompt != "review this" {
		t.Errorf("prompt/agent handlers not decoded: %+v", pre.Hooks[1:])
	}
}

// Continue resolves events by exact name against its declared list, so a typo
// never fires and must not be reported as configured.
func TestParseContinueHooks_UnknownEventIgnored(t *testing.T) {
	path := writeNamedTemp(t, "settings.json",
		`{"hooks": {"NotARealEvent": [{"hooks": [{"type": "command", "command": "echo x"}]}]}}`)
	h, err := ParseContinueHooks(path)
	if err != nil {
		t.Fatalf("ParseContinueHooks: %v", err)
	}
	if !h.Empty() {
		t.Errorf("an undeclared event must not be kept, got %+v", h.Hooks)
	}
}

func TestParseContinueHooks_AllDeclaredEvents(t *testing.T) {
	events := []string{
		"PreToolUse", "PostToolUse", "PostToolUseFailure", "PermissionRequest",
		"UserPromptSubmit", "SessionStart", "SessionEnd", "Stop", "Notification",
		"SubagentStart", "SubagentStop", "PreCompact", "ConfigChange",
		"TeammateIdle", "TaskCompleted", "WorktreeCreate", "WorktreeRemove",
	}
	body := `{"hooks": {`
	for i, e := range events {
		if i > 0 {
			body += ","
		}
		body += `"` + e + `": [{"hooks": [{"type":"command","command":"x"}]}]`
	}
	body += `}}`

	h, err := ParseContinueHooks(writeNamedTemp(t, "settings.json", body))
	if err != nil {
		t.Fatalf("ParseContinueHooks: %v", err)
	}
	if len(h.Hooks) != len(events) {
		t.Errorf("expected all %d declared events to decode, got %d", len(events), len(h.Hooks))
	}
}

func TestParseContinueHooks_DisableAllHooks(t *testing.T) {
	h, err := ParseContinueHooks(writeNamedTemp(t, "settings.json",
		`{"disableAllHooks": true, "hooks": {"SessionStart": [{"hooks": [{"type":"command","command":"x"}]}]}}`))
	if err != nil {
		t.Fatalf("ParseContinueHooks: %v", err)
	}
	if !h.DisableAllHooks {
		t.Error("disableAllHooks not decoded")
	}
	if !h.Empty() {
		t.Error("a file that disables hooks declares nothing that runs")
	}
}

// These settings files carry unrelated keys, so a file with no hooks block is an
// empty result rather than an error.
func TestParseContinueHooks_NoHooksBlock(t *testing.T) {
	h, err := ParseContinueHooks(writeNamedTemp(t, "settings.json", `{"someOtherSetting": 42}`))
	if err != nil {
		t.Fatalf("a settings file without hooks must not be an error: %v", err)
	}
	if !h.Empty() {
		t.Errorf("expected empty, got %+v", h)
	}
}

func TestParseContinueHooks_Malformed(t *testing.T) {
	if _, err := ParseContinueHooks(writeNamedTemp(t, "settings.json", `{"hooks":`)); err == nil {
		t.Error("expected an error for malformed JSON")
	}
}

func TestContinueHooks_EmptyNil(t *testing.T) {
	if !(*ContinueHooks)(nil).Empty() {
		t.Error("nil must be empty")
	}
}
