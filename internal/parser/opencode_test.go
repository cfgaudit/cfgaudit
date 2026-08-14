package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func writeOpenCode(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "opencode.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

// The shape differs from every other agent's: command is one array holding the
// executable and its arguments, and the env key is `environment`.
func TestParseOpenCodeConfig_LocalShape(t *testing.T) {
	path := writeOpenCode(t, `{
      "mcp": {"srv": {"type": "local", "command": ["node", "server.js", "--stdio"],
                      "environment": {"TOKEN": "x"}}}
    }`)
	c, err := ParseOpenCodeConfig(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	m := c.MCPServerMap()
	got := m["srv"]
	if got.Command != "node" {
		t.Errorf("command = %q, want the array's first element", got.Command)
	}
	if len(got.Args) != 2 || got.Args[0] != "server.js" {
		t.Errorf("args = %v, want the array's tail", got.Args)
	}
	if got.Env["TOKEN"] != "x" {
		t.Errorf("environment must map onto Env, got %v", got.Env)
	}
}

func TestParseOpenCodeConfig_RemoteShape(t *testing.T) {
	path := writeOpenCode(t, `{
      "mcp": {"r": {"type": "remote", "url": "https://mcp.example/mcp",
                    "headers": {"Authorization": "Bearer x"}}}
    }`)
	c, _ := ParseOpenCodeConfig(path)
	got := c.MCPServerMap()["r"]
	if got.URL != "https://mcp.example/mcp" || got.Headers["Authorization"] != "Bearer x" {
		t.Errorf("remote entry not mapped: %+v", got)
	}
}

// enabled defaults to true, so only an explicit false disables. A disabled
// server never starts, so reporting it would be a finding on nothing.
func TestParseOpenCodeConfig_DisabledDropped(t *testing.T) {
	path := writeOpenCode(t, `{
      "mcp": {
        "on":      {"type": "local", "command": ["a"]},
        "default": {"type": "local", "command": ["b"], "enabled": true},
        "off":     {"type": "local", "command": ["c"], "enabled": false}
      }}`)
	c, _ := ParseOpenCodeConfig(path)
	m := c.MCPServerMap()
	if len(m) != 2 {
		t.Fatalf("expected the disabled server dropped, got %v", m)
	}
	if _, ok := m["off"]; ok {
		t.Errorf("disabled server must not be mapped")
	}
}

// The file is JSONC despite the extension: opencode 1.18.18 resolves a config
// carrying comments and trailing commas, and two of 79 real files use them.
func TestParseOpenCodeConfig_JSONC(t *testing.T) {
	path := writeOpenCode(t, `{
      // the project's servers
      "mcp": {
        "srv": {
          "type": "local",
          "command": ["node", "x.js"],
        },
      },
    }`)
	c, err := ParseOpenCodeConfig(path)
	if err != nil {
		t.Fatalf("JSONC must decode: %v", err)
	}
	if len(c.MCPServerMap()) != 1 {
		t.Errorf("expected 1 server, got %v", c.MCPServerMap())
	}
}

func TestParseOpenCodeConfig_EmptyAndMalformed(t *testing.T) {
	c, err := ParseOpenCodeConfig(writeOpenCode(t, `{"model": "anthropic/x"}`))
	if err != nil || c.MCPServerMap() != nil {
		t.Errorf("a config with no mcp block yields no servers, got %v %v", c, err)
	}
	if _, err := ParseOpenCodeConfig(writeOpenCode(t, `{not json`)); err == nil {
		t.Errorf("expected an error for a malformed file")
	}
}
