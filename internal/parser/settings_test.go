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

func writeTempNamed(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

// tasks.json is JSONC: line/block comments and trailing commas must be tolerated,
// and a URL inside a string (containing //) must not be mistaken for a comment.
func TestParseVSCodeTasks_JSONC(t *testing.T) {
	src := `{
  // workspace tasks
  "version": "2.0.0",
  "tasks": [
    {
      "label": "boot", /* inline */
      "command": "echo https://example.com//path",
      "runOptions": { "runOn": "folderOpen" },
    },
  ],
}`
	v, err := ParseVSCodeTasks(writeTempNamed(t, "tasks.json", src))
	if err != nil {
		t.Fatalf("ParseVSCodeTasks: %v", err)
	}
	if len(v.Tasks) != 1 {
		t.Fatalf("expected 1 task, got %d", len(v.Tasks))
	}
	tk := v.Tasks[0]
	if tk.Label != "boot" || tk.RunOptions == nil || tk.RunOptions.RunOn != "folderOpen" {
		t.Errorf("unexpected task decode: %+v", tk)
	}
	if tk.Command != "echo https://example.com//path" {
		t.Errorf("URL in string was corrupted: %q", tk.Command)
	}
}

func TestParseVSCodeTasks_Malformed(t *testing.T) {
	if _, err := ParseVSCodeTasks(writeTempNamed(t, "tasks.json", `{ "tasks": [ }`)); err == nil {
		t.Error("expected error on malformed tasks.json")
	}
}

func TestParseVSCodeSettings_DottedKeysAndBoolField(t *testing.T) {
	src := `{
  // workspace settings
  "editor.tabSize": 2,
  "chat.tools.global.autoApprove": true,
  "chat.tools.autoApprove": false,
}`
	s, err := ParseVSCodeSettings(writeTempNamed(t, "settings.json", src))
	if err != nil {
		t.Fatalf("ParseVSCodeSettings: %v", err)
	}
	if v, ok := s.BoolField("chat.tools.global.autoApprove"); !ok || !v {
		t.Errorf("expected global autoApprove true, got (%v,%v)", v, ok)
	}
	if v, ok := s.BoolField("chat.tools.autoApprove"); !ok || v {
		t.Errorf("expected autoApprove present and false, got (%v,%v)", v, ok)
	}
	if _, ok := s.BoolField("editor.tabSize"); ok {
		t.Error("expected non-boolean key to report present=false")
	}
	if _, ok := s.BoolField("missing.key"); ok {
		t.Error("expected missing key to report present=false")
	}
}

// #614: the unwrapped root .mcp.json shape VS Code 1.139+ loads.
func TestUnwrappedMCPServers(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, ".mcp.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	got, err := UnwrappedMCPServers(write(`{"a":{"command":"npx","args":["x"]},"b":{"url":"https://e.example/mcp"},"$schema":"https://x","inputs":[],"c":{"type":"stdio"}}`))
	if err != nil || len(got) != 2 || got["a"].Command != "npx" || got["b"].URL == "" {
		t.Fatalf("expected servers a and b only, got %v (%v)", got, err)
	}
	for _, body := range []string{`{"mcpServers":{"a":{"command":"npx"}}}`, `{"servers":{"a":{"command":"npx"}}}`, `{"$schema":"https://x"}`} {
		if got, err := UnwrappedMCPServers(write(body)); err != nil || got != nil {
			t.Errorf("%s: expected nothing, got %v (%v)", body, got, err)
		}
	}
}
