package parser

import "encoding/json"

// geminiAgentMCPServer is one entry of the `mcpServers` block in a Gemini CLI
// agent file's frontmatter (packages/core/src/agents/agentLoader.ts). Gemini
// feeds these straight into MCPServerConfig, so they are ordinary MCP servers
// declared from a committed agent definition.
//
// Two spellings differ from the shared shape: `http_url` is Gemini's streamable
// HTTP endpoint (folded into URL below, as CodexMCP does for its own naming), and
// `trust` is the per-server "skip the confirmation prompt" flag.
type geminiAgentMCPServer struct {
	Command  string            `json:"command,omitempty"`
	Args     []string          `json:"args,omitempty"`
	Env      map[string]string `json:"env,omitempty"`
	URL      string            `json:"url,omitempty"`
	HTTPURL  string            `json:"http_url,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Type     string            `json:"type,omitempty"`
	Trust    bool              `json:"trust,omitempty"`
	Timeout  int               `json:"timeout,omitempty"`
	Describe string            `json:"description,omitempty"`
}

// GeminiAgentMCPServers decodes the `mcpServers:` block of a Gemini CLI agent
// file's frontmatter into the shared MCPServer shape, so the MCP rules apply
// unchanged.
//
// The value is a mapping of server name to config, like `.mcp.json`'s — not the
// list Claude Code's subagent frontmatter uses. Returns nil when the frontmatter
// carries no servers.
func GeminiAgentMCPServers(fm *Frontmatter) map[string]MCPServer {
	if fm == nil {
		return nil
	}
	raw, ok := fm.Raw["mcpServers"].(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]MCPServer)
	for name, cfg := range raw {
		b, err := json.Marshal(cfg)
		if err != nil {
			continue
		}
		var g geminiAgentMCPServer
		if err := json.Unmarshal(b, &g); err != nil {
			continue
		}
		url := g.URL
		if url == "" {
			url = g.HTTPURL
		}
		out[name] = MCPServer{
			Command: g.Command,
			Args:    g.Args,
			Env:     g.Env,
			URL:     url,
			Type:    g.Type,
			Headers: g.Headers,
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
