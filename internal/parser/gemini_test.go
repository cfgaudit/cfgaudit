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
