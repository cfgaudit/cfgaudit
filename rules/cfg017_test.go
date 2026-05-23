package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func TestCFG017_SettingsJSONSource(t *testing.T) {
	json := `{"mcpServers":{"inspector":{"command":"npx","args":["@modelcontextprotocol/inspector@1.0.0"],"dangerouslyAllowBrowser":true}}}`
	f := CFG017.Check(settingsTarget(t, json))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("expected Error severity, got %s", f[0].Severity)
	}
	if !strings.Contains(f[0].Message, "inspector") || !strings.Contains(f[0].Message, "dangerouslyAllowBrowser") {
		t.Errorf("expected message to name the server and flag, got: %s", f[0].Message)
	}
}

func TestCFG017_MCPJSONSource_AttributedToFile(t *testing.T) {
	tgt := &Target{
		SettingsFile:   ".claude/settings.json",
		Scope:          finding.ScopeProject,
		ProjectMCPFile: ".mcp.json",
		ProjectMCP: map[string]parser.MCPServer{
			"inspector": {Command: "npx", DangerouslyAllowBrowser: true},
		},
	}
	f := CFG017.Check(tgt)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding from .mcp.json, got %d", len(f))
	}
	if f[0].File != ".mcp.json" {
		t.Errorf("expected finding attributed to .mcp.json, got %q", f[0].File)
	}
}

func TestCFG017_False_NoFinding(t *testing.T) {
	f := CFG017.Check(settingsTarget(t, `{"mcpServers":{"ok":{"command":"npx","args":["pkg@1.0.0"],"dangerouslyAllowBrowser":false}}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding when flag is false, got %+v", f)
	}
}

func TestCFG017_Absent_NoFinding(t *testing.T) {
	f := CFG017.Check(settingsTarget(t, `{"mcpServers":{"ok":{"command":"npx","args":["pkg@1.0.0"]}}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding when flag absent, got %+v", f)
	}
}

func TestCFG017_NoSettings_NoFinding(t *testing.T) {
	if f := CFG017.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding when no servers present, got %+v", f)
	}
}
