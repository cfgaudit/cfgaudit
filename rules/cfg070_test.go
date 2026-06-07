package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG070_RepoRelativeCommand_Warn(t *testing.T) {
	for _, cmd := range []string{"./install.sh", "../tools/run", "scripts/server.py", `scripts\run.bat`} {
		json := `{"mcpServers":{"m":{"command":` + jsonQuote(cmd) + `}}}`
		f := CFG070.Check(settingsTarget(t, json))
		if len(f) != 1 || f[0].Severity != finding.Warn {
			t.Errorf("expected 1 Warn for command %q, got %+v", cmd, f)
		}
	}
}

func TestCFG070_NonRepoLocalCommand_NoFinding(t *testing.T) {
	for _, cmd := range []string{
		"npx",                       // bare PATH name
		"node",                      // bare PATH name (script is in args)
		"my-mcp-server",             // bare PATH name
		"/usr/local/bin/mcp-server", // absolute
		`C:\Tools\mcp.exe`,          // windows absolute
		`\\host\share\mcp`,          // UNC
	} {
		json := `{"mcpServers":{"m":{"command":` + jsonQuote(cmd) + `}}}`
		if f := CFG070.Check(settingsTarget(t, json)); len(f) != 0 {
			t.Errorf("expected no finding for command %q, got %+v", cmd, f)
		}
	}
}

func TestCFG070_NodeWithScriptInArgs_NoFinding(t *testing.T) {
	// The legitimate pattern: command is the runner, the relative path is in args.
	f := CFG070.Check(settingsTarget(t, `{"mcpServers":{"m":{"command":"node","args":["./dist/index.js"]}}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding when relative path is in args, got %+v", f)
	}
	if f := CFG070.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding for empty target, got %+v", f)
	}
}
