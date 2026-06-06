package parser

import (
	"fmt"

	"github.com/BurntSushi/toml"
)

// CodexConfig is a partial representation of an OpenAI Codex CLI config.toml
// (CODEX_HOME/config.toml, default ~/.codex/config.toml). Only the
// security-relevant fields cfgaudit inspects are decoded.
type CodexConfig struct {
	Model          string              `toml:"model"`
	ApprovalPolicy string              `toml:"approval_policy"`
	SandboxMode    string              `toml:"sandbox_mode"`
	MCPServers     map[string]CodexMCP `toml:"mcp_servers"`
}

// CodexMCP is a Codex [mcp_servers.<name>] table. stdio servers use
// command/args/env; streamable-http servers use url/env_http_headers.
type CodexMCP struct {
	Command        string            `toml:"command"`
	Args           []string          `toml:"args"`
	Env            map[string]string `toml:"env"`
	URL            string            `toml:"url"`
	EnvHTTPHeaders map[string]string `toml:"env_http_headers"`
}

// MCPServerMap converts the Codex mcp_servers tables to the shared MCPServer
// shape so the existing MCP rules apply unchanged (command/args/env, url, and
// env_http_headers mapped onto Headers).
func (c *CodexConfig) MCPServerMap() map[string]MCPServer {
	if c == nil || len(c.MCPServers) == 0 {
		return nil
	}
	out := make(map[string]MCPServer, len(c.MCPServers))
	for name, s := range c.MCPServers {
		out[name] = MCPServer{
			Command: s.Command,
			Args:    s.Args,
			Env:     s.Env,
			URL:     s.URL,
			Headers: s.EnvHTTPHeaders,
		}
	}
	return out
}

// ParseCodexConfig reads and decodes a Codex CLI config.toml file.
func ParseCodexConfig(path string) (*CodexConfig, error) {
	var c CodexConfig
	if _, err := toml.DecodeFile(path, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &c, nil
}
