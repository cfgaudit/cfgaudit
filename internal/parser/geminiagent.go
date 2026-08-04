package parser

import (
	"encoding/json"
	"strings"
)

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

// GeminiAgentMCPServers decodes the `mcp_servers:` block of a Gemini CLI agent
// file's frontmatter into the shared MCPServer shape, so the MCP rules apply
// unchanged.
//
// The key is **snake_case `mcp_servers`**, which is what the zod schema declares
// and what the loader reads (`markdown.mcp_servers`); `mcpServers` is only the
// camelCase name the internal MCPServerConfig map takes after conversion. The
// distinction matters twice over, because the local-agent schema is `.strict()`:
// a camelCase `mcpServers` key is not merely ignored, it fails validation and
// the whole agent file is rejected. Reading the wrong key would both miss every
// real block and report one that stops the agent from loading at all.
//
// The value is a mapping of server name to config, like `.mcp.json`'s — not the
// list Claude Code's subagent frontmatter uses. Returns nil when the frontmatter
// carries no servers.
func GeminiAgentMCPServers(fm *Frontmatter) map[string]MCPServer {
	if fm == nil {
		return nil
	}
	raw, ok := fm.Raw["mcp_servers"].(map[string]any)
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
			Trust:   g.Trust,
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// GeminiRemoteAgent holds the fields of a Gemini CLI *remote* agent definition:
// one that points at another agent over the network instead of running locally.
//
// Gemini decides an agent is remote when the frontmatter carries any of
// `agent_card_url`, `agent_card_json` or `auth` (agentLoader.ts,
// guessIntendedKind). The local and remote schemas are separate and `.strict()`,
// so a file is one or the other, never both.
type GeminiRemoteAgent struct {
	// CardURL is the A2A agent card the CLI fetches, after which it talks to the
	// agent that card describes.
	CardURL string
	// HasInlineCard reports whether the card is embedded in the committed file
	// (`agent_card_json`) rather than fetched.
	HasInlineCard bool
	// AuthSecrets holds the credential-bearing auth fields by name. The docs use
	// `$VAR` references throughout, but the schema is plain strings, so a literal
	// is accepted.
	AuthSecrets map[string]string
}

// geminiAuthSecretFields are the auth-block fields that carry a credential:
// apiKey's `key`, http Bearer's `token`, and http Basic's `username`/`password`.
// `scheme`, `name` and `scopes` name a mechanism rather than a secret.
var geminiAuthSecretFields = []string{"key", "token", "username", "password"}

// GeminiAgentRemote decodes the remote-agent fields of a Gemini agent file's
// frontmatter. Returns nil when the file declares none of them, which is the
// ordinary local-agent case.
func GeminiAgentRemote(fm *Frontmatter) *GeminiRemoteAgent {
	if fm == nil {
		return nil
	}
	out := &GeminiRemoteAgent{}
	if s, ok := fm.Raw["agent_card_url"].(string); ok {
		out.CardURL = strings.TrimSpace(s)
	}
	if _, ok := fm.Raw["agent_card_json"]; ok {
		out.HasInlineCard = true
	}
	if auth, ok := fm.Raw["auth"].(map[string]any); ok {
		for _, field := range geminiAuthSecretFields {
			if v, ok := auth[field].(string); ok && strings.TrimSpace(v) != "" {
				if out.AuthSecrets == nil {
					out.AuthSecrets = map[string]string{}
				}
				out.AuthSecrets[field] = v
			}
		}
	}
	if out.CardURL == "" && !out.HasInlineCard && len(out.AuthSecrets) == 0 {
		return nil
	}
	return out
}
