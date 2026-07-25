package parser

import (
	"encoding/json"
	"fmt"
	"os"
)

// GeminiSettings is a partial representation of a Gemini CLI settings.json
// (~/.gemini/settings.json or .gemini/settings.json). Only the security-relevant
// fields cfgaudit inspects are decoded; mcpServers shares Claude Code's shape so
// the existing MCP rules apply once it is attached to a Target.
type GeminiSettings struct {
	General    *GeminiGeneral       `json:"general,omitempty"`
	Tools      *GeminiTools         `json:"tools,omitempty"`
	Security   *GeminiSecurity      `json:"security,omitempty"`
	MCPServers map[string]MCPServer `json:"mcpServers,omitempty"`

	// Hooks maps a hook event to matcher groups, each carrying a list of handlers
	// — the nested Claude-Code shape (verified against gemini-cli
	// packages/core/src/hooks/types.ts HookDefinition), so the shared HookGroup /
	// HookCommand types decode it. Gemini's extra fields (a group's `sequential`,
	// a handler's `env`/`description`) are simply ignored. The event names are
	// exact PascalCase — SessionStart, BeforeTool, … — with no normalization on
	// Gemini's side; SessionStart is the only zero-click one (CFG086).
	Hooks map[string][]HookGroup `json:"hooks,omitempty"`

	// HooksConfig is Gemini's SEPARATE kill-switch block (top-level hooksConfig,
	// not under hooks). Absent means the hook system is on.
	HooksConfig *GeminiHooksConfig `json:"hooksConfig,omitempty"`
}

// GeminiHooksConfig is Gemini CLI's hooksConfig block — the switch that turns the
// hook system off, the analogue of Copilot's disableAllHooks. Enabled is a pointer
// so an explicit false (the committed suppressor) is distinguishable from absent,
// which defaults to enabled. Disabled is a per-name list of hooks not to run,
// keyed by each handler's `name`.
type GeminiHooksConfig struct {
	Enabled  *bool    `json:"enabled,omitempty"`
	Disabled []string `json:"disabled,omitempty"`
}

// HooksDisabled reports whether this settings file globally switches the hook
// system off via hooksConfig.enabled: false. Absent defaults to enabled, matching
// Gemini's schema default, so only an explicit false suppresses.
func (s *GeminiSettings) HooksDisabled() bool {
	return s != nil && s.HooksConfig != nil && s.HooksConfig.Enabled != nil && !*s.HooksConfig.Enabled
}

// DisabledHookNames returns the set of hook names switched off by name via
// hooksConfig.disabled, so a handler Gemini would not run is not reported.
func (s *GeminiSettings) DisabledHookNames() map[string]bool {
	if s == nil || s.HooksConfig == nil || len(s.HooksConfig.Disabled) == 0 {
		return nil
	}
	set := make(map[string]bool, len(s.HooksConfig.Disabled))
	for _, name := range s.HooksConfig.Disabled {
		set[name] = true
	}
	return set
}

// GeminiGeneral carries the approval-mode setting (analog to Claude Code's
// defaultMode). "auto_edit" auto-approves all edit tools; "plan" is read-only.
type GeminiGeneral struct {
	DefaultApprovalMode string `json:"defaultApprovalMode,omitempty"`
}

// GeminiTools carries the sandbox settings (analog to Claude Code's sandbox).
type GeminiTools struct {
	SandboxAllowedPaths  []string `json:"sandboxAllowedPaths,omitempty"`
	SandboxNetworkAccess bool     `json:"sandboxNetworkAccess,omitempty"`
}

// GeminiSecurity carries Gemini's security section. BlockGitExtensions is a
// pointer so an explicit `false` (a committed footgun) is distinguishable from
// the field being absent.
type GeminiSecurity struct {
	BlockGitExtensions *bool    `json:"blockGitExtensions,omitempty"`
	AllowedExtensions  []string `json:"allowedExtensions,omitempty"`
}

// ParseGeminiSettings reads and decodes a Gemini CLI settings.json file.
func ParseGeminiSettings(path string) (*GeminiSettings, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is resolved by the CLI from a user-supplied directory
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var s GeminiSettings
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &s, nil
}
