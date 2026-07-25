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
// Only mcpServers is modelled here. The rest of qwen's security surface —
// tools.approvalMode (values up to "yolo"), tools.autoAccept, tools.sandbox, the
// hooks block, and security.folderTrust.enabled — is real but drives rules that
// are split into follow-ups (see the #390 scoping decision), so parsing it now
// would be dead config. A dedicated type rather than reusing GeminiSettings,
// because qwen's approval model diverges (tools.approvalMode, not
// general.defaultApprovalMode), so the two are not interchangeable.
//
// The severity framing for those follow-ups: qwen ships folder trust DISABLED by
// default (security.folderTrust.enabled ?? false), so a committed .qwen/settings.json
// is applied with no trust prompt — the inverse of Cursor/Codex/Grok, which gate
// project config on trust.
type QwenSettings struct {
	MCPServers map[string]QwenMCP `json:"mcpServers,omitempty"`
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
