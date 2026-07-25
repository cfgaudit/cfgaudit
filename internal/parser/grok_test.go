package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func writeGrok(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

// Grok uses [mcp_servers] (snake_case) with an untagged transport: stdio sets
// command/args/env, streamable-http sets url/headers. No type discriminator.
func TestParseGrokConfig_MCPServers(t *testing.T) {
	p := writeGrok(t, "config.toml", `
[mcp_servers.local]
command = "npx"
args = ["-y", "tool@latest"]
env = { TOKEN = "x" }

[mcp_servers.remote]
url = "http://mcp.example/sse"
headers = { Authorization = "Bearer abc" }
`)
	c, err := ParseGrokConfig(p)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	m := c.MCPServerMap()
	if len(m) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(m))
	}
	if m["local"].Command != "npx" || len(m["local"].Args) != 2 || m["local"].Env["TOKEN"] != "x" {
		t.Errorf("stdio server decoded wrong: %+v", m["local"])
	}
	if m["remote"].URL != "http://mcp.example/sse" || m["remote"].Headers["Authorization"] != "Bearer abc" {
		t.Errorf("http server decoded wrong: %+v", m["remote"])
	}
}

func TestParseGrokConfig_NoMCP(t *testing.T) {
	p := writeGrok(t, "config.toml", "[ui]\ntheme = \"dark\"\n")
	c, err := ParseGrokConfig(p)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(c.MCPServerMap()) != 0 {
		t.Errorf("expected no servers (only [ui]), got %+v", c.MCPServerMap())
	}
}

func TestParseGrokConfig_Malformed(t *testing.T) {
	if _, err := ParseGrokConfig(writeGrok(t, "config.toml", "not = = toml")); err == nil {
		t.Error("expected error for malformed TOML")
	}
}

// Grok hook files share Claude Code's shape: {"hooks": {event: [{matcher, hooks}]}}.
func TestParseGrokHooks(t *testing.T) {
	p := writeGrok(t, "guard.json", `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"./guard.sh"}]}]}}`)
	h, err := ParseGrokHooks(p)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	groups := h.Hooks["PreToolUse"]
	if len(groups) != 1 || len(groups[0].Hooks) != 1 || groups[0].Hooks[0].Command != "./guard.sh" {
		t.Errorf("hook decoded wrong: %+v", h.Hooks)
	}
}

func TestParseGrokHooks_Malformed(t *testing.T) {
	if _, err := ParseGrokHooks(writeGrok(t, "h.json", `{not json`)); err == nil {
		t.Error("expected error for malformed JSON")
	}
}
