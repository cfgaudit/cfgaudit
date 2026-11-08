// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func writeGemini(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestParseGeminiSettings(t *testing.T) {
	path := writeGemini(t, `{
		"general": {"defaultApprovalMode": "auto_edit"},
		"tools": {"sandboxAllowedPaths": ["/", "./build"], "sandboxNetworkAccess": true},
		"security": {"blockGitExtensions": false},
		"mcpServers": {"x": {"command": "npx", "args": ["pkg"]}}
	}`)

	gs, err := ParseGeminiSettings(path)
	if err != nil {
		t.Fatalf("ParseGeminiSettings: %v", err)
	}
	if gs.General == nil || gs.General.DefaultApprovalMode != "auto_edit" {
		t.Errorf("defaultApprovalMode: %+v", gs.General)
	}
	if gs.Tools == nil || !gs.Tools.SandboxNetworkAccess || len(gs.Tools.SandboxAllowedPaths) != 2 {
		t.Errorf("tools: %+v", gs.Tools)
	}
	if gs.Security == nil || gs.Security.BlockGitExtensions == nil || *gs.Security.BlockGitExtensions {
		t.Errorf("expected blockGitExtensions explicitly false, got %+v", gs.Security)
	}
	if len(gs.MCPServers) != 1 {
		t.Errorf("expected 1 mcpServer, got %d", len(gs.MCPServers))
	}
}

func TestParseGeminiSettings_BlockGitExtensionsAbsentIsNil(t *testing.T) {
	path := writeGemini(t, `{"security": {"allowedExtensions": ["a"]}}`)
	gs, err := ParseGeminiSettings(path)
	if err != nil {
		t.Fatalf("ParseGeminiSettings: %v", err)
	}
	if gs.Security.BlockGitExtensions != nil {
		t.Errorf("expected nil BlockGitExtensions when absent, got %v", *gs.Security.BlockGitExtensions)
	}
}

// The nested matcher-group hook shape decodes into the shared HookGroup type, and
// Gemini's extra fields (a group's `sequential`, a handler's `env`) are ignored.
func TestParseGeminiSettings_Hooks(t *testing.T) {
	path := writeGemini(t, `{
		"hooks": {
			"SessionStart": [
				{ "matcher": "*", "sequential": true, "hooks": [
					{ "type": "command", "name": "boot", "command": "./setup.sh", "env": {"A": "1"}, "timeout": 30 }
				]}
			],
			"BeforeTool": [
				{ "matcher": "run_shell_command", "hooks": [ { "type": "command", "command": "./guard.sh" } ] }
			]
		}
	}`)
	gs, err := ParseGeminiSettings(path)
	if err != nil {
		t.Fatalf("ParseGeminiSettings: %v", err)
	}
	ss := gs.Hooks["SessionStart"]
	if len(ss) != 1 || len(ss[0].Hooks) != 1 {
		t.Fatalf("SessionStart shape: %+v", ss)
	}
	if h := ss[0].Hooks[0]; h.Command != "./setup.sh" || h.Name != "boot" || h.Type != "command" {
		t.Errorf("SessionStart handler: %+v", h)
	}
	if len(gs.Hooks["BeforeTool"]) != 1 {
		t.Errorf("expected BeforeTool group, got %+v", gs.Hooks["BeforeTool"])
	}
}

// hooksConfig is a separate top-level block; enabled: false is the kill switch and
// disabled is a per-name list. Absent enabled defaults to on.
func TestParseGeminiSettings_HooksConfig(t *testing.T) {
	off := writeGemini(t, `{"hooksConfig": {"enabled": false, "disabled": ["boot"]}}`)
	gs, err := ParseGeminiSettings(off)
	if err != nil {
		t.Fatalf("ParseGeminiSettings: %v", err)
	}
	if !gs.HooksDisabled() {
		t.Error("expected HooksDisabled() true when hooksConfig.enabled is false")
	}
	if d := gs.DisabledHookNames(); !d["boot"] {
		t.Errorf("expected boot in DisabledHookNames, got %+v", d)
	}

	absent := writeGemini(t, `{"hooks": {"SessionStart": []}}`)
	gs2, err := ParseGeminiSettings(absent)
	if err != nil {
		t.Fatalf("ParseGeminiSettings: %v", err)
	}
	if gs2.HooksDisabled() {
		t.Error("expected HooksDisabled() false when hooksConfig is absent")
	}
}

// gemini-cli reads settings.json as JSON.parse(stripJsonComments(content)), the
// code qwen-code forked, so a commented file is valid input to the agent and must
// not fail the scan.
func TestParseGeminiSettings_JSONCComments(t *testing.T) {
	path := writeGemini(t, `{
		// which approval mode this project runs in
		"general": {"defaultApprovalMode": "auto_edit"},
		/* block comment */
		"ui": {"theme": "dark"}
	}`)
	gs, err := ParseGeminiSettings(path)
	if err != nil {
		t.Fatalf("parse commented settings: %v", err)
	}
	if gs.General == nil || gs.General.DefaultApprovalMode != "auto_edit" {
		t.Fatalf("expected defaultApprovalMode through the comments, got %+v", gs.General)
	}
}

// mcp.excluded and the tool lists read their shape loosely, so an odd value
// costs only the policy, not the file (#1517).
func TestGeminiSettings_PolicyFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	for src, want := range map[string]int{
		`{"mcp":{"excluded":["a","b"]},"tools":{"exclude":"x"}}`: 2,
		`{"mcp":"x"}`: 0,
		`{}`:          0,
	} {
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := ParseGeminiSettings(path)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		if got := s.ExcludedMCPServers(); len(got) != want {
			t.Errorf("%s: got %q", src, got)
		}
	}
}

func TestResolveGeminiEnvVars(t *testing.T) {
	env := map[string]string{"HOST": "https://c.example", "E": ""}
	for in, want := range map[string]string{
		"$HOST/v1":             "https://c.example/v1",
		"${HOST}":              "https://c.example",
		"${MISSING:-http://d}": "http://d",
		"${MISSING:-}x":        "x",
		"${E:-z}":              "",
		"$MISSING":             "$MISSING",
		"${MISSING}":           "${MISSING}",
		"plain":                "plain",
	} {
		if got := ResolveGeminiEnvVars(in, env); got != want {
			t.Errorf("%s: got %q, want %q", in, got, want)
		}
	}
}

func TestParseGeminiSettingsEnv(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(p, []byte(`{// c
	  "telemetry": {"otlpEndpoint": "$X", "enabled": true},
	  "mcpServers": {"s": {"url": "${X}/mcp", "headers": {"a": "$K"}, "timeout": 5, "args": ["$X"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := ParseGeminiSettingsEnv(p, map[string]string{"X": "https://e.example", "K": "v"})
	if err != nil {
		t.Fatal(err)
	}
	if s.Telemetry.OtlpEndpoint != "https://e.example" || s.MCPServers["s"].URL != "https://e.example/mcp" || s.MCPServers["s"].Headers["a"] != "v" || s.MCPServers["s"].Args[0] != "https://e.example" {
		t.Fatalf("got %+v %+v", s.Telemetry, s.MCPServers["s"])
	}
	if s, err := ParseGeminiSettingsEnv(p, nil); err != nil || s.Telemetry.OtlpEndpoint != "$X" {
		t.Fatalf("no env: %v %+v", err, s)
	}
	if err := os.WriteFile(p, []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseGeminiSettingsEnv(p, map[string]string{"X": "y"}); err == nil {
		t.Fatal("broken file parsed")
	}
	if _, err := ParseGeminiSettingsEnv(filepath.Join(dir, "missing.json"), map[string]string{"X": "y"}); err == nil {
		t.Fatal("missing file parsed")
	}
	if err := os.WriteFile(p, []byte(`{"mcpServers": []}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseGeminiSettingsEnv(p, map[string]string{"X": "y"}); err == nil {
		t.Fatal("wrong type parsed")
	}
}

func TestGeminiEnvTelemetry(t *testing.T) {
	if tel, _ := GeminiEnvTelemetry(map[string]string{"X": "1"}); tel != nil {
		t.Fatal("no telemetry vars")
	}
	tel, key := GeminiEnvTelemetry(map[string]string{"GEMINI_TELEMETRY_ENABLED": "yes", "GEMINI_TELEMETRY_LOG_PROMPTS": "1",
		"OTEL_EXPORTER_OTLP_ENDPOINT": "https://o", "GEMINI_TELEMETRY_OTLP_ENDPOINT": " https://g "})
	if tel == nil || *tel.Enabled || !*tel.LogPrompts || tel.OtlpEndpoint != "https://g" || key != "GEMINI_TELEMETRY_OTLP_ENDPOINT" {
		t.Fatalf("got %+v %s", tel, key)
	}
	if tel, key := GeminiEnvTelemetry(map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "https://o"}); tel.OtlpEndpoint != "https://o" || key != "OTEL_EXPORTER_OTLP_ENDPOINT" || tel.Enabled != nil {
		t.Fatalf("otel: %+v", tel)
	}
}
