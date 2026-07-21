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
	// Notify is a program (argv) Codex spawns on events; a committed value runs
	// attacker-controlled code, so it is scanned by the command-content rules.
	Notify []string `toml:"notify"`

	// ChatGPTBaseURL and the per-provider base_url are model endpoints the API key
	// is sent to; a cleartext remote value leaks it (CFG071).
	ChatGPTBaseURL string                   `toml:"chatgpt_base_url"`
	ModelProviders map[string]CodexProvider `toml:"model_providers"`
}

// CodexProvider is a [model_providers.<name>] table.
type CodexProvider struct {
	Name    string `toml:"name"`
	BaseURL string `toml:"base_url"`
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

// ApplyProjectLayerDenylist clears the fields Codex refuses to honour from a
// project-local config layer, so cfgaudit does not report configuration the CLI
// ignores.
//
// Codex loads a committed .codex/config.toml as a project layer, but guards a
// subset of keys against it. From codex-rs/config/src/loader/mod.rs:
//
//	// Project-local config comes from repository contents, so it should not get to
//	// choose where a user's credentials are sent or which local commands are run.
//	const PROJECT_LOCAL_CONFIG_DENYLIST: &[&str] = &[
//	    "openai_base_url", "chatgpt_base_url", "apps_mcp_product_sku",
//	    "model_provider", "model_providers", "notify", "profile", "profiles",
//	    "experimental_realtime_webrtc_call_base_url",
//	    "experimental_realtime_ws_base_url", "otel",
//	];
//
// Of those, cfgaudit reads three: notify (a command site) plus chatgpt_base_url
// and model_providers (CFG071). Reporting them from a project file would be a
// pure false positive — the same reasoning that keeps Devin's user-only
// sandbox.excluded unmodelled.
//
// approval_policy, sandbox_mode and mcp_servers are deliberately NOT on the
// upstream denylist, which is why CFG063/CFG064 and the MCP family do apply to a
// committed file.
func (c *CodexConfig) ApplyProjectLayerDenylist() {
	if c == nil {
		return
	}
	c.Notify = nil
	c.ChatGPTBaseURL = ""
	c.ModelProviders = nil
}
