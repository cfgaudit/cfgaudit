package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func TestCFG019_BashCommand(t *testing.T) {
	f := CFG019.Check(settingsTarget(t, `{"mcpServers":{"m":{"command":"bash","args":["-c","echo hi"]}}}`))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error finding, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "bash") {
		t.Errorf("expected message to name the shell, got: %s", f[0].Message)
	}
}

func TestCFG019_VariantsMatched(t *testing.T) {
	for _, cmd := range []string{"/bin/bash", "/usr/bin/zsh", "sh", "PowerShell", "cmd.exe", "C:\\\\Windows\\\\System32\\\\cmd.exe", "pwsh"} {
		json := `{"mcpServers":{"m":{"command":"` + cmd + `"}}}`
		if f := CFG019.Check(settingsTarget(t, json)); len(f) != 1 {
			t.Errorf("expected 1 finding for command %q, got %d", cmd, len(f))
		}
	}
}

func TestCFG019_MCPJSONSource(t *testing.T) {
	tgt := &Target{
		SettingsFile:   ".claude/settings.json",
		Scope:          finding.ScopeProject,
		ProjectMCPFile: ".mcp.json",
		ProjectMCP:     map[string]parser.MCPServer{"m": {Command: "/bin/sh", Args: []string{"-c", "x"}}},
	}
	f := CFG019.Check(tgt)
	if len(f) != 1 || f[0].File != ".mcp.json" {
		t.Fatalf("expected 1 finding attributed to .mcp.json, got %+v", f)
	}
}

func TestCFG019_NonShellCommands_NoFinding(t *testing.T) {
	for _, cmd := range []string{"npx", "node", "python3", "/usr/local/bin/mcp-server", "deno", "uvx"} {
		json := `{"mcpServers":{"m":{"command":"` + cmd + `"}}}`
		if f := CFG019.Check(settingsTarget(t, json)); len(f) != 0 {
			t.Errorf("expected no finding for command %q, got %+v", cmd, f)
		}
	}
}

func TestCFG019_NoSettings_NoFinding(t *testing.T) {
	if f := CFG019.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding when no servers present, got %+v", f)
	}
}
