package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// CodexHookHandler is one entry in a matcher group's `hooks` array.
//
// Codex tags the variant with `type`. Only "command" carries a shell string:
// discovery skips "prompt" and "agent" with the warning that they "are not
// supported yet", so neither is a command site.
//
// CommandWindows is the platform-specific spelling (`commandWindows`, alias
// `command_windows`). A hook that only sets it still runs a command, on Windows,
// so both are collected.
type CodexHookHandler struct {
	Type           string `json:"type,omitempty" toml:"type"`
	Command        string `json:"command,omitempty" toml:"command"`
	CommandWindows string `json:"commandWindows,omitempty" toml:"commandWindows"`
	// CommandWindowsSnake is Codex's documented serde alias for the same field.
	CommandWindowsSnake string `json:"command_windows,omitempty" toml:"command_windows"`
	Timeout             int    `json:"timeout,omitempty" toml:"timeout"`
	StatusMessage       string `json:"statusMessage,omitempty" toml:"statusMessage"`
}

// Commands returns every shell string this handler declares, in a stable order:
// the cross-platform command first, then the Windows spellings. Empty for a
// prompt or agent handler, which Codex does not execute.
func (h CodexHookHandler) Commands() []string {
	if h.Type != "" && h.Type != "command" {
		return nil
	}
	var out []string
	for _, c := range []string{h.Command, h.CommandWindows, h.CommandWindowsSnake} {
		if c != "" {
			out = append(out, c)
		}
	}
	return out
}

// CodexMatcherGroup is one `{matcher, hooks}` group under an event name.
type CodexMatcherGroup struct {
	Matcher string             `json:"matcher,omitempty" toml:"matcher"`
	Hooks   []CodexHookHandler `json:"hooks,omitempty" toml:"hooks"`
}

// CodexHooks is the event → matcher groups map shared by Codex's two hook
// representations: a `.codex/hooks.json` file (whose groups sit under a top-level
// "hooks" key) and an inline `[hooks]` table in `.codex/config.toml`.
type CodexHooks struct {
	Events map[string][]CodexMatcherGroup
}

// EventNames returns the configured event names in a stable order.
func (h *CodexHooks) EventNames() []string {
	if h == nil {
		return nil
	}
	names := make([]string, 0, len(h.Events))
	for name := range h.Events {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Empty reports whether no event carries a group.
func (h *CodexHooks) Empty() bool {
	if h == nil {
		return true
	}
	for _, groups := range h.Events {
		if len(groups) > 0 {
			return false
		}
	}
	return true
}

// CodexHookEventsToml mirrors Codex's HookEventsToml
// (codex-rs/config/src/hook_config.rs): one named field per declared lifecycle
// event, in both the JSON and TOML spellings.
//
// Named fields rather than a map, for two reasons. Codex's own discovery warns
// and ignores an event name it does not declare, so a map would let a typo be
// reported as a configured event. And in config.toml the `[hooks]` table also
// carries a `state` sub-table, whose shape is a map, not a list of groups: a
// permissive map would turn a user's ordinary `[hooks.state.…]` entry into a
// hard decode error.
//
// `state` is deliberately not decoded at all. Only User and SessionFlags layers
// may write hook state (codex-rs/hooks/src/config_rules.rs), so a trusted_hash
// committed to a project file is inert and reporting it would be a false finding.
type CodexHookEventsToml struct {
	PreToolUse       []CodexMatcherGroup `json:"PreToolUse,omitempty" toml:"PreToolUse"`
	PermissionReq    []CodexMatcherGroup `json:"PermissionRequest,omitempty" toml:"PermissionRequest"`
	PostToolUse      []CodexMatcherGroup `json:"PostToolUse,omitempty" toml:"PostToolUse"`
	PreCompact       []CodexMatcherGroup `json:"PreCompact,omitempty" toml:"PreCompact"`
	PostCompact      []CodexMatcherGroup `json:"PostCompact,omitempty" toml:"PostCompact"`
	SessionStart     []CodexMatcherGroup `json:"SessionStart,omitempty" toml:"SessionStart"`
	SessionEnd       []CodexMatcherGroup `json:"SessionEnd,omitempty" toml:"SessionEnd"`
	UserPromptSubmit []CodexMatcherGroup `json:"UserPromptSubmit,omitempty" toml:"UserPromptSubmit"`
	SubagentStart    []CodexMatcherGroup `json:"SubagentStart,omitempty" toml:"SubagentStart"`
	SubagentStop     []CodexMatcherGroup `json:"SubagentStop,omitempty" toml:"SubagentStop"`
	Stop             []CodexMatcherGroup `json:"Stop,omitempty" toml:"Stop"`
}

// Hooks converts the decoded events to the event → groups map, keeping only
// events that carry at least one group. Returns nil when none do.
func (e *CodexHookEventsToml) Hooks() *CodexHooks {
	if e == nil {
		return nil
	}
	byName := map[string][]CodexMatcherGroup{
		"PreToolUse":        e.PreToolUse,
		"PermissionRequest": e.PermissionReq,
		"PostToolUse":       e.PostToolUse,
		"PreCompact":        e.PreCompact,
		"PostCompact":       e.PostCompact,
		"SessionStart":      e.SessionStart,
		"SessionEnd":        e.SessionEnd,
		"UserPromptSubmit":  e.UserPromptSubmit,
		"SubagentStart":     e.SubagentStart,
		"SubagentStop":      e.SubagentStop,
		"Stop":              e.Stop,
	}
	out := make(map[string][]CodexMatcherGroup)
	for name, groups := range byName {
		if len(groups) > 0 {
			out[name] = groups
		}
	}
	if len(out) == 0 {
		return nil
	}
	return &CodexHooks{Events: out}
}

// codexHooksFile is the shape of a hooks.json: an optional description plus the
// events under a "hooks" key (Codex's HooksFile struct).
type codexHooksFile struct {
	Description string              `json:"description,omitempty"`
	Hooks       CodexHookEventsToml `json:"hooks,omitempty"`
}

// ParseCodexHooksJSON reads and decodes a .codex/hooks.json.
func ParseCodexHooksJSON(path string) (*CodexHooks, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is resolved by the CLI from a user-supplied directory
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var f codexHooksFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return f.Hooks.Hooks(), nil
}
