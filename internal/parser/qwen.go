package parser

import (
	"encoding/json"
	"fmt"
	"os"
)

// QwenSettings is the subset of qwen-code's .qwen/settings.json that cfgaudit
// reads today. qwen-code (QwenLM/qwen-code) is a heavily diverged fork of Gemini
// CLI: the settings directory is .qwen (SETTINGS_DIRECTORY_NAME = '.qwen', verified
// against storage-paths-lite.ts) and the file is settings.json.
//
// The rest of qwen's security surface — tools.sandbox and security.folderTrust —
// is real but drives rules split into follow-ups (see the #390 scoping decision),
// so parsing it now would be dead config. A dedicated type rather than reusing
// GeminiSettings, because qwen's approval model diverges (tools.approvalMode, not
// general.defaultApprovalMode) and its hooks kill switch is top-level
// disableAllHooks (not Gemini's hooksConfig.enabled), so the two are not
// interchangeable.
//
// The severity framing: qwen ships folder trust DISABLED by default
// (security.folderTrust.enabled ?? false, and isTrustedFolder() then defaults to
// true), so a committed .qwen/settings.json — mcpServers, tools.approvalMode, and
// hooks — is applied with no trust prompt, the inverse of Cursor/Codex/Grok.
type QwenSettings struct {
	Tools      *QwenTools         `json:"tools,omitempty"`
	MCPServers map[string]QwenMCP `json:"mcpServers,omitempty"`

	// Hooks is qwen's hooks block: an event name → matcher groups (the shared
	// Claude/Gemini shape). It is decoded lazily via HookGroups() rather than as
	// map[string][]HookGroup, because qwen skips the reserved keys enabled/disabled/
	// notifications *inside* the hooks object (a legacy hooksConfig migration), and
	// a non-array value there (e.g. `enabled: true`) would otherwise fail the whole
	// parse. Event names are exact PascalCase (qwen does not normalize them).
	Hooks map[string]json.RawMessage `json:"hooks,omitempty"`

	// DisableAllHooks is qwen's top-level kill switch (verified: replaces gemini's
	// hooksConfig.enabled). true switches the whole hook system off.
	DisableAllHooks bool `json:"disableAllHooks,omitempty"`
}

// qwenReservedHookKeys are the keys qwen skips inside the hooks object because they
// are not event names — leftovers of the migrated hooksConfig block.
var qwenReservedHookKeys = map[string]bool{"enabled": true, "disabled": true, "notifications": true}

// HookGroups decodes the hooks block into the shared HookGroup shape, skipping the
// reserved non-event keys and any value that is not a matcher-group array. Returns
// nil when there are no real event hooks.
func (s *QwenSettings) HookGroups() map[string][]HookGroup {
	if s == nil || len(s.Hooks) == 0 {
		return nil
	}
	out := make(map[string][]HookGroup, len(s.Hooks))
	for event, raw := range s.Hooks {
		if qwenReservedHookKeys[event] {
			continue
		}
		var groups []HookGroup
		if err := json.Unmarshal(raw, &groups); err != nil {
			continue // not an event-groups array (e.g. a stray scalar) — skip
		}
		if len(groups) > 0 {
			out[event] = groups
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// HooksDisabled reports whether disableAllHooks switches the hook system off.
func (s *QwenSettings) HooksDisabled() bool {
	return s != nil && s.DisableAllHooks
}

// QwenTools carries qwen's tools.* approval surface. ApprovalMode is
// tools.approvalMode (plan/default/auto-edit/auto/yolo); only "yolo" blanket
// auto-approves every tool call including shell, so it is the value CFG091 flags.
// tools.autoAccept is deliberately not modelled: it is vestigial in qwen (no
// consumer in the approval path — verified against source), so reading it would
// invite a finding for an effect that does not exist.
type QwenTools struct {
	ApprovalMode string `json:"approvalMode,omitempty"`
}

// QwenMCP is one mcpServers entry. qwen's MCPServerConfig carries the same core
// transport fields as Gemini's (command/args/env for stdio; url/headers for SSE)
// plus httpUrl for streamable-HTTP servers. httpUrl is folded into the shared
// MCPServer.URL so the remote-transport MCP rules see it.
type QwenMCP struct {
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	URL     string            `json:"url,omitempty"`
	HTTPURL string            `json:"httpUrl,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

// MCPServerMap converts the qwen mcpServers block to the shared MCPServer shape so
// the existing MCP rules (CFG010–021, CFG049–059) apply unchanged, attributed to
// the settings file. httpUrl is folded into URL when url is absent.
func (s *QwenSettings) MCPServerMap() map[string]MCPServer {
	if s == nil || len(s.MCPServers) == 0 {
		return nil
	}
	out := make(map[string]MCPServer, len(s.MCPServers))
	for name, m := range s.MCPServers {
		url := m.URL
		if url == "" {
			url = m.HTTPURL
		}
		out[name] = MCPServer{
			Command: m.Command,
			Args:    m.Args,
			Env:     m.Env,
			URL:     url,
			Headers: m.Headers,
		}
	}
	return out
}

// ParseQwenSettings reads and decodes a qwen-code settings.json file. A malformed
// file is an error, so a config that is silently not being scanned is reported
// rather than mistaken for empty.
func ParseQwenSettings(path string) (*QwenSettings, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is resolved by the CLI from a user-supplied directory
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var s QwenSettings
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &s, nil
}
