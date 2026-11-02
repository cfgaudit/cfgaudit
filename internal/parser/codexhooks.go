// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/scanroot"
)

// CodexHookHandler is one entry in a matcher group's `hooks` array.
//
// Codex tags the variant with `type`. Only "command" carries a shell string;
// "mcp_tool" calls a tool on an MCP server with a committed input (#972);
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

	// Server, Tool and Input belong to a type "mcp_tool" handler: when the hook
	// fires, Codex calls Tool on the MCP server Server with the committed Input
	// (HookHandlerConfig::McpTool in codex-rs/protocol/src/hooks.rs at
	// rust-v0.166.0, #972).
	Server string         `json:"server,omitempty" toml:"server"`
	Tool   string         `json:"tool,omitempty" toml:"tool"`
	Input  map[string]any `json:"input,omitempty" toml:"input"`
}

// MCPToolCall reports the server and tool of an mcp_tool handler that Codex
// runs under event. Like Codex's discovery (codex-rs/hooks/src/engine/
// discovery.rs), it skips one under SessionEnd ("SessionEnd MCP hooks are not
// supported") and one whose server or tool is empty.
func (h CodexHookHandler) MCPToolCall(event string) (server, tool string, ok bool) {
	if h.Type != "mcp_tool" || event == "SessionEnd" {
		return "", "", false
	}
	server, tool = strings.TrimSpace(h.Server), strings.TrimSpace(h.Tool)
	return server, tool, server != "" && tool != ""
}

// InputString is one string value in an mcp_tool handler's input, with its
// key path ("command", "args[1]", "options.path").
type InputString struct {
	Path, Value string
}

// InputStrings returns every string value in the handler's input, nested ones
// included, sorted by key path.
func (h CodexHookHandler) InputStrings() []InputString {
	var out []InputString
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch x := v.(type) {
		case string:
			out = append(out, InputString{Path: path, Value: x})
		case map[string]any:
			for k, e := range x {
				p := k
				if path != "" {
					p = path + "." + k
				}
				walk(p, e)
			}
		case []any:
			for i, e := range x {
				walk(path+"["+strconv.Itoa(i)+"]", e)
			}
		}
	}
	walk("", map[string]any(h.Input))
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// Commands returns every shell string this handler declares, in a stable order:
// the cross-platform command first, then the Windows spellings. Empty for a
// prompt or agent handler, which Codex does not execute, and for an mcp_tool
// handler, which runs no shell (see MCPToolCall).
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
// (codex-rs/config/src/hook_config.rs; codex-rs/protocol/src/hooks.rs since
// rust-v0.166.0): one named field per declared lifecycle event, in both the
// JSON and TOML spellings. PreModelRequest and PostModelRequest came in
// rust-v0.164.0 (openai/codex#55144, "observation-only model request lifecycle
// hooks"); their command handlers run like any other (#753).
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
	PreModelRequest  []CodexMatcherGroup `json:"PreModelRequest,omitempty" toml:"PreModelRequest"`
	PostModelRequest []CodexMatcherGroup `json:"PostModelRequest,omitempty" toml:"PostModelRequest"`
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
	Interrupt        []CodexMatcherGroup `json:"Interrupt,omitempty" toml:"Interrupt"`
}

// Hooks converts the decoded events to the event → groups map, keeping only
// events that carry at least one group. Returns nil when none do.
func (e *CodexHookEventsToml) Hooks() *CodexHooks {
	if e == nil {
		return nil
	}
	byName := map[string][]CodexMatcherGroup{
		"PreModelRequest":   e.PreModelRequest,
		"PostModelRequest":  e.PostModelRequest,
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
		"Interrupt":         e.Interrupt,
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
	data, err := scanroot.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var f codexHooksFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return f.Hooks.Hooks(), nil
}
