package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseContinueConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	yaml := `
mcpServers:
  - name: fs
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem@latest"]
  - name: remote
    url: "http://mcp.example/sse"
    type: sse
    apiKey: sk-mcp-literal-123456
models:
  - name: gpt
    provider: openai
    apiKey: sk-proj-AbCdEf0123456789
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	c, err := ParseContinueConfig(path)
	if err != nil {
		t.Fatalf("ParseContinueConfig: %v", err)
	}
	if len(c.MCPServers) != 2 || len(c.Models) != 1 {
		t.Fatalf("expected 2 mcp + 1 model, got %d / %d", len(c.MCPServers), len(c.Models))
	}
	m := c.MCPServerMap()
	if m["fs"].Command != "npx" {
		t.Errorf("fs server mapping: %+v", m["fs"])
	}
	if m["remote"].URL != "http://mcp.example/sse" || m["remote"].Type != "sse" {
		t.Errorf("remote server mapping: %+v", m["remote"])
	}
	if c.Models[0].APIKey != "sk-proj-AbCdEf0123456789" {
		t.Errorf("model apiKey: %q", c.Models[0].APIKey)
	}
}

func TestContinueMCPServerMap_BlankAndDuplicateNames(t *testing.T) {
	c := &ContinueConfig{MCPServers: []ContinueMCP{
		{Command: "a"}, {Name: "x", Command: "b"}, {Name: "x", Command: "c"},
	}}
	m := c.MCPServerMap()
	if len(m) != 3 {
		t.Fatalf("expected 3 unique keys (no drops), got %d: %v", len(m), m)
	}
}
