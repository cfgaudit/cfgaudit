package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func writeZed(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestParseZedSettings_ContextServers(t *testing.T) {
	path := writeZed(t, `{
	  "theme": "One Dark",
	  "context_servers": {
	    "local": { "command": "some-command", "args": ["a", "b"], "env": {"K": "v"} },
	    "remote": { "url": "https://example.com/mcp", "headers": {"Authorization": "Bearer x"} }
	  }
	}`)
	servers, err := ParseZedSettings(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(servers))
	}
	if got := servers["local"].Command; got != "some-command" {
		t.Errorf("command = %q", got)
	}
	if got := servers["local"].Args; len(got) != 2 || got[0] != "a" {
		t.Errorf("args = %v", got)
	}
	if got := servers["remote"].URL; got != "https://example.com/mcp" {
		t.Errorf("url = %q", got)
	}
	if got := servers["remote"].Headers["Authorization"]; got != "Bearer x" {
		t.Errorf("header = %q", got)
	}
}

// Zed ships a heavily commented default settings file, so JSONC must decode.
func TestParseZedSettings_JSONC(t *testing.T) {
	path := writeZed(t, `{
	  // the assistant's MCP servers
	  "context_servers": {
	    "local": { "command": "x" }, // trailing comment
	  },
	}`)
	servers, err := ParseZedSettings(path)
	if err != nil {
		t.Fatalf("parse JSONC: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
}

func TestParseZedSettings_NoKey(t *testing.T) {
	path := writeZed(t, `{"theme": "One Dark"}`)
	servers, err := ParseZedSettings(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(servers) != 0 {
		t.Errorf("expected no servers, got %v", servers)
	}
}

func TestParseZedSettings_Malformed(t *testing.T) {
	path := writeZed(t, `{not json`)
	if _, err := ParseZedSettings(path); err == nil {
		t.Error("expected an error for malformed settings, got nil")
	}
}

func TestParseZedSettings_Missing(t *testing.T) {
	if _, err := ParseZedSettings(filepath.Join(t.TempDir(), "nope.json")); !os.IsNotExist(errUnwrap(err)) {
		t.Errorf("expected a not-exist error, got %v", err)
	}
}

// errUnwrap peels the fmt.Errorf wrapper so os.IsNotExist can see the cause.
func errUnwrap(err error) error {
	type unwrapper interface{ Unwrap() error }
	for {
		u, ok := err.(unwrapper)
		if !ok {
			return err
		}
		err = u.Unwrap()
	}
}
