package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func writeQwen(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

// mcpServers map onto the shared MCPServer shape, and httpUrl is folded into URL
// so the remote-transport MCP rules see a streamable-HTTP server.
func TestParseQwenSettings_MCPServerMap(t *testing.T) {
	path := writeQwen(t, `{
		"mcpServers": {
			"local":  { "command": "node", "args": ["srv.js"], "env": {"K": "v"} },
			"remote": { "httpUrl": "https://mcp.example/stream", "headers": {"Authorization": "Bearer x"} },
			"sse":    { "url": "https://mcp.example/sse" }
		}
	}`)
	qs, err := ParseQwenSettings(path)
	if err != nil {
		t.Fatalf("ParseQwenSettings: %v", err)
	}
	m := qs.MCPServerMap()
	if len(m) != 3 {
		t.Fatalf("expected 3 servers, got %d: %+v", len(m), m)
	}
	if m["local"].Command != "node" || len(m["local"].Args) != 1 || m["local"].Env["K"] != "v" {
		t.Errorf("local: %+v", m["local"])
	}
	if m["remote"].URL != "https://mcp.example/stream" {
		t.Errorf("httpUrl should fold into URL, got %q", m["remote"].URL)
	}
	if m["remote"].Headers["Authorization"] != "Bearer x" {
		t.Errorf("remote headers: %+v", m["remote"].Headers)
	}
	if m["sse"].URL != "https://mcp.example/sse" {
		t.Errorf("sse url: %q", m["sse"].URL)
	}
}

// url wins over httpUrl when both are present (url is the explicit SSE endpoint).
func TestParseQwenSettings_URLWinsOverHTTPURL(t *testing.T) {
	path := writeQwen(t, `{"mcpServers": {"s": {"url": "https://a", "httpUrl": "https://b"}}}`)
	qs, err := ParseQwenSettings(path)
	if err != nil {
		t.Fatalf("ParseQwenSettings: %v", err)
	}
	if got := qs.MCPServerMap()["s"].URL; got != "https://a" {
		t.Errorf("expected url to win, got %q", got)
	}
}

func TestParseQwenSettings_EmptyIsNilMap(t *testing.T) {
	path := writeQwen(t, `{}`)
	qs, err := ParseQwenSettings(path)
	if err != nil {
		t.Fatalf("ParseQwenSettings: %v", err)
	}
	if m := qs.MCPServerMap(); m != nil {
		t.Errorf("expected nil map for no servers, got %+v", m)
	}
}

func TestParseQwenSettings_Malformed(t *testing.T) {
	path := writeQwen(t, `{"mcpServers": `)
	if _, err := ParseQwenSettings(path); err == nil {
		t.Error("expected an error for malformed JSON")
	}
}

// HookGroups decodes event arrays and skips the reserved enabled/disabled/
// notifications keys that qwen tolerates inside the hooks object — a bool or
// string-array there must NOT fail the whole parse.
func TestParseQwenSettings_HookGroups(t *testing.T) {
	path := writeQwen(t, `{
		"hooks": {
			"enabled": true,
			"disabled": ["some-hook"],
			"notifications": {"x": 1},
			"SessionStart": [ { "hooks": [ { "type": "command", "command": "./boot.sh" } ] } ],
			"PreToolUse": [ { "matcher": "run_shell_command", "hooks": [ { "type": "command", "command": "./guard.sh" } ] } ]
		}
	}`)
	qs, err := ParseQwenSettings(path)
	if err != nil {
		t.Fatalf("ParseQwenSettings: %v (reserved keys must not break the parse)", err)
	}
	g := qs.HookGroups()
	if len(g) != 2 {
		t.Fatalf("expected 2 event groups (SessionStart, PreToolUse), got %d: %+v", len(g), g)
	}
	if len(g["SessionStart"]) != 1 || g["SessionStart"][0].Hooks[0].Command != "./boot.sh" {
		t.Errorf("SessionStart: %+v", g["SessionStart"])
	}
	if _, ok := g["enabled"]; ok {
		t.Error("reserved key 'enabled' must not appear as an event")
	}
}

func TestParseQwenSettings_HooksDisabled(t *testing.T) {
	on := writeQwen(t, `{"disableAllHooks": true, "hooks": {"SessionStart": [{"hooks":[{"type":"command","command":"x"}]}]}}`)
	qs, err := ParseQwenSettings(on)
	if err != nil {
		t.Fatalf("ParseQwenSettings: %v", err)
	}
	if !qs.HooksDisabled() {
		t.Error("expected HooksDisabled() true when disableAllHooks is set")
	}

	off := writeQwen(t, `{"hooks": {"SessionStart": []}}`)
	qs2, _ := ParseQwenSettings(off)
	if qs2.HooksDisabled() {
		t.Error("expected HooksDisabled() false when disableAllHooks is absent")
	}
	if qs2.HookGroups() != nil {
		t.Error("expected nil HookGroups when the only event array is empty")
	}
}
