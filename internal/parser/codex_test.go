package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseCodexConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	toml := `
model = "gpt-5.1"
approval_policy = "never"
sandbox_mode = "danger-full-access"

[mcp_servers.docs]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem"]
env = { TOKEN = "sk-secret" }

[mcp_servers.remote]
url = "http://mcp.example/sse"
env_http_headers = { Authorization = "Bearer xyz" }
`
	if err := os.WriteFile(path, []byte(toml), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	c, err := ParseCodexConfig(path)
	if err != nil {
		t.Fatalf("ParseCodexConfig: %v", err)
	}
	if c.ApprovalPolicy != "never" || c.SandboxMode != "danger-full-access" {
		t.Errorf("approval/sandbox: %q / %q", c.ApprovalPolicy, c.SandboxMode)
	}
	m := c.MCPServerMap()
	if len(m) != 2 {
		t.Fatalf("expected 2 mcp servers, got %d", len(m))
	}
	if m["docs"].Command != "npx" || m["docs"].Env["TOKEN"] != "sk-secret" {
		t.Errorf("stdio server mapping: %+v", m["docs"])
	}
	if m["remote"].URL != "http://mcp.example/sse" || m["remote"].Headers["Authorization"] != "Bearer xyz" {
		t.Errorf("http server mapping (env_http_headers -> Headers): %+v", m["remote"])
	}
}

func TestParseCodexConfig_Empty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(`model = "gpt-5.1"`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	c, err := ParseCodexConfig(path)
	if err != nil {
		t.Fatalf("ParseCodexConfig: %v", err)
	}
	if c.MCPServerMap() != nil || c.ApprovalPolicy != "" {
		t.Errorf("expected empty config to yield no servers / empty policy, got %+v", c)
	}
}
