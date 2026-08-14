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
