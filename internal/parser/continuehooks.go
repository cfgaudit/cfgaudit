package parser

import (
	"encoding/json"
	"fmt"
	"os"
)

// continueHookEvents are the event names Continue's CLI declares
// (extensions/cli/src/hooks/types.ts HOOK_EVENT_NAMES). Listed explicitly so a
// typo in a committed file is not reported as a configured event: Continue looks
// the event up by name, and a name it does not declare simply never fires.
var continueHookEvents = map[string]bool{
	"PreToolUse": true, "PostToolUse": true, "PostToolUseFailure": true,
	"PermissionRequest": true, "UserPromptSubmit": true, "SessionStart": true,
	"SessionEnd": true, "Stop": true, "Notification": true,
	"SubagentStart": true, "SubagentStop": true, "PreCompact": true,
	"ConfigChange": true, "TeammateIdle": true, "TaskCompleted": true,
	"WorktreeCreate": true, "WorktreeRemove": true,
}

// ContinueHooks is the hooks portion of a Continue CLI settings file
// (.continue/settings.json, .continue/settings.local.json).
//
// The shape is Claude Code's — event name → matcher groups → handlers — which is
// deliberate: the loader's own header says it reads "hooks from settings files in
// the same locations as Claude Code", and it additionally reads
// .claude/settings.json and .claude/settings.local.json from the same project for
// cross-compatibility. Handler types are "command" (shell), "http" (POST),
// "prompt" and "agent" (both LLM calls carrying prompt text).
//
// There is no trust gate anywhere in this path: HookService.doInitialize loads
// the config and fireEvent runs the handlers, with disableAllHooks as the only
// switch. A committed SessionStart command hook therefore runs on repo open,
// which is what makes CFG086 apply here where it does not to Codex.
type ContinueHooks struct {
	Hooks map[string][]HookGroup `json:"hooks,omitempty"`
	// DisableAllHooks turns every hook off. Continue sets its global disable flag
	// if ANY loaded settings file carries it; per scanned file, a file that
	// disables hooks declares nothing that runs.
	DisableAllHooks bool `json:"disableAllHooks,omitempty"`
}

// Empty reports whether the file declared no hooks cfgaudit would scan.
func (h *ContinueHooks) Empty() bool {
	if h == nil || h.DisableAllHooks {
		return true
	}
	for _, groups := range h.Hooks {
		if len(groups) > 0 {
			return false
		}
	}
	return true
}

// ParseContinueHooks reads a Continue settings file and returns its hooks,
// filtered to the event names Continue declares. A file without a hooks block
// decodes to an empty result rather than an error, because these settings files
// carry unrelated keys too.
func ParseContinueHooks(path string) (*ContinueHooks, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is resolved by the CLI from a user-supplied directory
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var h ContinueHooks
	if err := json.Unmarshal(data, &h); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	for name, groups := range h.Hooks {
		if !continueHookEvents[name] || len(groups) == 0 {
			delete(h.Hooks, name)
		}
	}
	if len(h.Hooks) == 0 {
		h.Hooks = nil
	}
	return &h, nil
}
