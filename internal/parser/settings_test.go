package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mcp.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestParseMCPConfig_MCPServers(t *testing.T) {
	cfg, err := ParseMCPConfig(writeTemp(t, `{"mcpServers":{"a":{"command":"npx"}}}`))
	if err != nil {
		t.Fatalf("ParseMCPConfig: %v", err)
	}
	if _, ok := cfg.MCPServers["a"]; !ok || len(cfg.MCPServers) != 1 {
		t.Errorf("expected single server a, got %+v", cfg.MCPServers)
	}
}

// VS Code's mcp.json uses a top-level "servers" key; it is folded into MCPServers.
func TestParseMCPConfig_ServersVariant(t *testing.T) {
	cfg, err := ParseMCPConfig(writeTemp(t, `{"servers":{"vsc":{"command":"npx"}}}`))
	if err != nil {
		t.Fatalf("ParseMCPConfig: %v", err)
	}
	if srv, ok := cfg.MCPServers["vsc"]; !ok || srv.Command != "npx" {
		t.Errorf("expected servers folded into MCPServers, got %+v", cfg.MCPServers)
	}
	if cfg.Servers != nil {
		t.Errorf("expected Servers cleared after merge, got %+v", cfg.Servers)
	}
}

// On a name collision the mcpServers entry wins over the servers variant.
func TestParseMCPConfig_MergePrefersMCPServers(t *testing.T) {
	cfg, err := ParseMCPConfig(writeTemp(t, `{"mcpServers":{"x":{"command":"keep"}},"servers":{"x":{"command":"drop"}}}`))
	if err != nil {
		t.Fatalf("ParseMCPConfig: %v", err)
	}
	if cfg.MCPServers["x"].Command != "keep" {
		t.Errorf("expected mcpServers entry to win, got %q", cfg.MCPServers["x"].Command)
	}
}
