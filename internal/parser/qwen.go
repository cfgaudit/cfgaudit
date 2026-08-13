package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
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

	// Proxy is the top-level proxy URL: "Proxy URL for CLI HTTP requests. Takes
	// precedence over proxy environment variables when --proxy is not provided."
	//
	// Measured against qwen 0.21.11: a committed workspace .qwen/settings.json
	// carrying proxy = "http://127.0.0.1:<port>" made the CLI issue
	// "CONNECT api.openai.com:443" to that listener, so this key routes the
	// agent's model traffic, credential header included.
	Proxy string `json:"proxy,omitempty"`

	// Memory carries the auto-skill confirmation pair.
	Memory *QwenMemory `json:"memory,omitempty"`

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
// consumer in the approval path), so reading it would invite a finding for an
// effect that does not exist. Re-verified against the shipped qwen 0.21.11
// bundle when #472 re-proposed it: the string occurs exactly four times, and all
// four are declarations rather than consumers — twice in V1_TO_V2_MIGRATION_MAP
// ("autoAccept" → "tools.autoAccept"), once in V1_INDICATOR_KEYS, and once in
// the settings schema itself. Nothing reads the value.
type QwenTools struct {
	ApprovalMode string `json:"approvalMode,omitempty"`

	// SandboxImage is the container image the agent's sandbox runs from:
	// "Sandbox image URI used by Docker/Podman when --sandbox-image and
	// QWEN_SANDBOX_IMAGE are not set."
	//
	// The resolution order in the shipped bundle is
	// argv.sandboxImage ?? QWEN_SANDBOX_IMAGE ?? settings.tools?.sandboxImage
	// ?? packageJson.config.sandboxImageUri, and loadSandboxConfig only returns
	// an image at all when a sandbox command was resolved. So a committed image
	// is latent: it decides the container only once someone turns the sandbox on.
	SandboxImage string `json:"sandboxImage,omitempty"`

	// Sandbox is tools.sandbox (bool or a command string), kept only as the gate
	// telling whether SandboxImage can take effect from settings alone. It is
	// deliberately not a finding of its own: enabling a sandbox hardens.
	Sandbox *json.RawMessage `json:"sandbox,omitempty"`
}

// QwenMemory is the memory block. Only the auto-skill pair is decoded.
//
// Both are pointers because both defaults matter and neither is the zero value:
// EnableAutoSkill defaults to false, AutoSkillConfirm defaults to TRUE. So the
// weakening value here is `false`, the inverse of the disable* keys where `true`
// is. Confirmed in the shipped bundle: DEFAULT_QWEN_MEMORY_SETTINGS carries
// { enableAutoSkill: false, autoSkillConfirm: true }, and the config resolves
// `settings.memory?.autoSkillConfirm ?? true`.
type QwenMemory struct {
	EnableAutoSkill  *bool `json:"enableAutoSkill,omitempty"`
	AutoSkillConfirm *bool `json:"autoSkillConfirm,omitempty"`
}

// SandboxEnabledInSettings reports whether tools.sandbox turns a sandbox on from
// the settings file itself. An absent key, an explicit false, and a non-scalar
// value all count as "not from settings": the sandbox may still be switched on by
// --sandbox or QWEN_SANDBOX, which is why the image is reported as latent rather
// than dropped.
func (s *QwenSettings) SandboxEnabledInSettings() bool {
	if s == nil || s.Tools == nil || s.Tools.Sandbox == nil {
		return false
	}
	var b bool
	if err := json.Unmarshal(*s.Tools.Sandbox, &b); err == nil {
		return b
	}
	var str string
	if err := json.Unmarshal(*s.Tools.Sandbox, &str); err == nil {
		return strings.TrimSpace(str) != "" && !strings.EqualFold(strings.TrimSpace(str), "false")
	}
	return false
}

// AutoSkillsSavedUnconfirmed reports whether auto-generated skills land in the
// skill library with no confirmation, which needs BOTH keys: the feature on and
// the confirmation off.
func (s *QwenSettings) AutoSkillsSavedUnconfirmed() bool {
	if s == nil || s.Memory == nil {
		return false
	}
	enabled := s.Memory.EnableAutoSkill != nil && *s.Memory.EnableAutoSkill
	confirmOff := s.Memory.AutoSkillConfirm != nil && !*s.Memory.AutoSkillConfirm
	return enabled && confirmOff
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
