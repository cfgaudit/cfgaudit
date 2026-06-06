package parser

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// ContinueConfig is a partial representation of a Continue config.yaml
// (.continue/config.yaml or ~/.continue/config.yaml). mcpServers is a list (not
// a map as in Claude Code's .mcp.json); models carry inline provider credentials.
type ContinueConfig struct {
	MCPServers []ContinueMCP   `yaml:"mcpServers"`
	Models     []ContinueModel `yaml:"models"`
}

// ContinueMCP is one entry of the mcpServers list. stdio servers use
// command/args/env; sse/streamable-http servers use url/type and may carry an
// inline apiKey.
type ContinueMCP struct {
	Name    string            `yaml:"name"`
	Command string            `yaml:"command"`
	Args    []string          `yaml:"args"`
	Env     map[string]string `yaml:"env"`
	URL     string            `yaml:"url"`
	Type    string            `yaml:"type"`
	APIKey  string            `yaml:"apiKey"`
}

// ContinueModel is one entry of the models list. A literal apiKey is a hardcoded
// credential; the continue-proxy provider instead uses apiKeyLocation (a
// reference), which is the safe pattern.
type ContinueModel struct {
	Name     string `yaml:"name"`
	Provider string `yaml:"provider"`
	APIKey   string `yaml:"apiKey"`
}

// MCPServerMap converts the mcpServers list to the shared MCPServer shape so the
// existing MCP rules apply unchanged. Entries are keyed by name (unique-ified for
// blank or duplicate names) so no server is silently dropped.
func (c *ContinueConfig) MCPServerMap() map[string]MCPServer {
	if c == nil || len(c.MCPServers) == 0 {
		return nil
	}
	out := make(map[string]MCPServer, len(c.MCPServers))
	for i, s := range c.MCPServers {
		key := strings.TrimSpace(s.Name)
		if key == "" {
			key = "server" + strconv.Itoa(i)
		}
		for _, dup := out[key]; dup; _, dup = out[key] {
			key += "#" + strconv.Itoa(i)
		}
		out[key] = MCPServer{
			Command: s.Command,
			Args:    s.Args,
			Env:     s.Env,
			URL:     s.URL,
			Type:    s.Type,
		}
	}
	return out
}

// ParseContinueConfig reads and decodes a Continue config.yaml file.
func ParseContinueConfig(path string) (*ContinueConfig, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is resolved by the CLI from a user-supplied directory
	if err != nil {
		return nil, err
	}
	var c ContinueConfig
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &c, nil
}
