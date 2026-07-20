package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func writeDevin(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestParseDevinConfig_Keys(t *testing.T) {
	path := writeDevin(t, `{
	  "permissions": { "allow": ["Read(**)", "Exec(git)"], "deny": ["Exec(sudo)"] },
	  "mcpServers": { "local": { "command": "npx", "args": ["a"], "env": {"K":"v"} } },
	  "hooks": { "SessionStart": [ { "matcher": "*", "hooks": [ { "type": "command", "command": "./x.sh" } ] } ] }
	}`)
	c, err := ParseDevinConfig(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.Permissions == nil || len(c.Permissions.Allow) != 2 {
		t.Errorf("permissions = %+v", c.Permissions)
	}
	if got := c.MCPServers["local"].Command; got != "npx" {
		t.Errorf("command = %q", got)
	}
	groups := c.Hooks["SessionStart"]
	if len(groups) != 1 || len(groups[0].Hooks) != 1 || groups[0].Hooks[0].Command != "./x.sh" {
		t.Errorf("hooks = %+v", c.Hooks)
	}
}

// Devin spells the remote discriminator `transport`; it is folded into Type so
// the shared MCP rules only read one field.
func TestParseDevinConfig_TransportFoldedIntoType(t *testing.T) {
	path := writeDevin(t, `{"mcpServers":{"r":{"url":"https://x/mcp","transport":"sse"}}}`)
	c, err := ParseDevinConfig(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := c.MCPServers["r"].Type; got != "sse" {
		t.Errorf("expected transport folded into Type, got %q", got)
	}
}

// An explicit type wins; transport must not clobber it.
func TestParseDevinConfig_ExplicitTypeWins(t *testing.T) {
	path := writeDevin(t, `{"mcpServers":{"r":{"url":"https://x/mcp","type":"http","transport":"sse"}}}`)
	c, err := ParseDevinConfig(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := c.MCPServers["r"].Type; got != "http" {
		t.Errorf("expected explicit type kept, got %q", got)
	}
}

func TestParseDevinConfig_EmptyAndMalformed(t *testing.T) {
	empty := writeDevin(t, `{}`)
	c, err := ParseDevinConfig(empty)
	if err != nil {
		t.Fatalf("parse empty: %v", err)
	}
	if len(c.MCPServers) != 0 || len(c.Hooks) != 0 || c.Permissions != nil {
		t.Errorf("expected a zero config, got %+v", c)
	}

	bad := writeDevin(t, `{not json`)
	if _, err := ParseDevinConfig(bad); err == nil {
		t.Error("expected an error for a malformed config")
	}
}
