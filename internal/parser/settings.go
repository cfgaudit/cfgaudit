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

// CommandHelper is the {"type":"command","command":"…"} shape used by the
// statusLine and fileSuggestion settings.
type CommandHelper struct {
	Type    string `json:"type,omitempty"`
	Command string `json:"command,omitempty"`
}

// StringField returns a top-level key expected to hold a JSON string. Missing
// keys and values of the wrong type both yield "" — accessors stay type-tolerant
// so a single mistyped key never aborts the whole parse (CFG012 reports the
// type mismatch separately). Used for the command-bearing keys Claude Code
// executes besides hooks (apiKeyHelper, awsCredentialExport, awsAuthRefresh,
// gcpAuthRefresh, otelHeadersHelper) — an RCE surface a repo-controlled
// settings.json can abuse, the same class as a malicious hook (CVE-2025-59536).
func (s *Settings) StringField(key string) string {
	raw, ok := s.Raw[key]
	if !ok {
		return ""
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return ""
	}
	return v
}

// CommandHelperField returns the .command of a {"type":..,"command":..} object
// key (statusLine, fileSuggestion). Missing or mistyped values yield "".
func (s *Settings) CommandHelperField(key string) string {
	raw, ok := s.Raw[key]
	if !ok {
		return ""
	}
	var v CommandHelper
	if err := json.Unmarshal(raw, &v); err != nil {
		return ""
	}
	return v.Command
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
	Command                 string            `json:"command,omitempty"`
	Args                    []string          `json:"args,omitempty"`
	AlwaysAllow             []string          `json:"alwaysAllow,omitempty"`
	Env                     map[string]string `json:"env,omitempty"`
	DangerouslyAllowBrowser bool              `json:"dangerouslyAllowBrowser,omitempty"`
}

// MCPConfig is a project-level .mcp.json file: a bare object whose mcpServers
// map carries the same shape as the inline mcpServers block in settings.json.
// This is the file enableAllProjectMcpServers / enabledMcpjsonServers auto-approve,
// so MCP rules must reach it, not just the inline settings.json servers.
type MCPConfig struct {
	MCPServers map[string]MCPServer `json:"mcpServers,omitempty"`
}

// ParseMCPConfig reads and decodes a project .mcp.json file.
func ParseMCPConfig(path string) (*MCPConfig, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is resolved by the CLI from a user-supplied directory
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var c MCPConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &c, nil
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
