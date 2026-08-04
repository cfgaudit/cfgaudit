package parser

import (
	"encoding/json"
	"fmt"
	"os"
)

// KimiPluginManifest is a partial representation of a Kimi Code plugin's
// `kimi.plugin.json` (agent-core/src/plugin/manifest.ts). Only the fields
// cfgaudit inspects are decoded.
//
// The manifest sits at the plugin root and is read when the plugin is installed
// or reloaded, never from a scanned repository: Kimi's PluginManager loads from
// the install store under the user's Kimi home. So this describes a repo that
// *is* a plugin, which is the author-side case the .claude-plugin/ handling
// already covers.
type KimiPluginManifest struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`

	// SystemPrompt is instructions contributed to the agent's system prompt while
	// the plugin is enabled, and SystemPromptPath a "./" path to a file appended
	// after it. Both are trusted text a committed manifest injects, the class
	// CFG092 covers for Kimi's agent files.
	SystemPrompt     string `json:"systemPrompt,omitempty"`
	SystemPromptPath string `json:"systemPromptPath,omitempty"`

	// MCPServers is an object keyed by server name, the same shape as the
	// mcpServers block of an .mcp.json, so the shared MCP rules apply unchanged.
	MCPServers map[string]MCPServer `json:"mcpServers,omitempty"`
}

// Empty reports whether the manifest declared nothing cfgaudit inspects.
func (m *KimiPluginManifest) Empty() bool {
	return m == nil || (m.SystemPrompt == "" && m.SystemPromptPath == "" && len(m.MCPServers) == 0)
}

// ParseKimiPluginManifest reads and decodes a kimi.plugin.json.
func ParseKimiPluginManifest(path string) (*KimiPluginManifest, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is resolved by the CLI from a user-supplied plugin tree
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var m KimiPluginManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &m, nil
}
