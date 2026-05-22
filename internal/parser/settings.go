package parser

import (
	"encoding/json"
	"fmt"
	"os"
)

// Settings is a partial representation of Claude Code's settings.json.
// Unknown keys are preserved in the raw map so rules can inspect them.
type Settings struct {
	Permissions *Permissions           `json:"permissions,omitempty"`
	Env         map[string]string      `json:"env,omitempty"`
	Hooks       map[string][]HookGroup `json:"hooks,omitempty"`
	MCPServers  map[string]MCPServer   `json:"mcpServers,omitempty"`

	// Raw holds the full decoded document for rules that need arbitrary access.
	Raw map[string]json.RawMessage `json:"-"`
}

type Permissions struct {
	Allow []string `json:"allow,omitempty"`
	Deny  []string `json:"deny,omitempty"`
}

// HookGroup is the per-event hook entry: a matcher plus the commands it triggers.
// Claude Code's hooks schema nests command definitions under a matcher group.
type HookGroup struct {
	Matcher string        `json:"matcher,omitempty"`
	Hooks   []HookCommand `json:"hooks,omitempty"`
}

type HookCommand struct {
	Type    string `json:"type,omitempty"`
	Command string `json:"command,omitempty"`
	Timeout int    `json:"timeout,omitempty"`
}

type MCPServer struct {
	Command      string            `json:"command,omitempty"`
	Args         []string          `json:"args,omitempty"`
	AlwaysAllow  []string          `json:"alwaysAllow,omitempty"`
	Env          map[string]string `json:"env,omitempty"`
}

// ParseSettings reads and decodes a settings.json file.
func ParseSettings(path string) (*Settings, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is resolved by the CLI from a user-supplied directory
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return ParseSettingsBytes(data, path)
}

// ParseSettingsBytes decodes settings.json from an in-memory byte slice.
// path is used only for error messages.
func ParseSettingsBytes(data []byte, path string) (*Settings, error) {
	var s Settings
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &s.Raw); err != nil {
		return nil, fmt.Errorf("parse raw %s: %w", path, err)
	}
	return &s, nil
}
