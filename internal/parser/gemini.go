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
