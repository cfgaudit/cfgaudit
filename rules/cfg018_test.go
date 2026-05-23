package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func TestCFG018_EnvHost(t *testing.T) {
	f := CFG018.Check(settingsTarget(t, `{"mcpServers":{"c":{"command":"mcp-server","env":{"HOST":"0.0.0.0"}}}}`))
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 Warn finding, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "HOST") || !strings.Contains(f[0].Message, "NeighborJack") {
		t.Errorf("expected message to name env.HOST and NeighborJack, got: %s", f[0].Message)
	}
}

func TestCFG018_ArgForms(t *testing.T) {
	cases := []string{
		`{"mcpServers":{"c":{"command":"s","args":["--host","0.0.0.0"]}}}`,
		`{"mcpServers":{"c":{"command":"s","args":["--host=0.0.0.0"]}}}`,
		`{"mcpServers":{"c":{"command":"s","args":["0.0.0.0:3000"]}}}`,
		`{"mcpServers":{"c":{"command":"s","args":["tcp://0.0.0.0:3000"]}}}`,
		`{"mcpServers":{"c":{"command":"s","args":["--bind","[::]"]}}}`,
	}
	for _, json := range cases {
		f := CFG018.Check(settingsTarget(t, json))
		if len(f) != 1 {
			t.Errorf("expected 1 finding for %s, got %d", json, len(f))
		}
	}
}

func TestCFG018_MCPJSONSource(t *testing.T) {
	tgt := &Target{
		SettingsFile:   ".claude/settings.json",
		Scope:          finding.ScopeProject,
		ProjectMCPFile: ".mcp.json",
		ProjectMCP: map[string]parser.MCPServer{
			"c": {Command: "mcp-server", Args: []string{"--host", "0.0.0.0"}},
		},
	}
	f := CFG018.Check(tgt)
	if len(f) != 1 || f[0].File != ".mcp.json" {
		t.Fatalf("expected 1 finding attributed to .mcp.json, got %+v", f)
	}
}

func TestCFG018_NoFalsePositiveOnRealNetworks(t *testing.T) {
	// 10.0.0.0 and 100.0.0.0 are real addresses, not the all-interfaces bind.
	for _, addr := range []string{"10.0.0.0", "100.0.0.0", "127.0.0.1", "192.168.0.0"} {
		json := `{"mcpServers":{"c":{"command":"s","env":{"HOST":"` + addr + `"}}}}`
		if f := CFG018.Check(settingsTarget(t, json)); len(f) != 0 {
			t.Errorf("expected no finding for %s, got %+v", addr, f)
		}
	}
}

func TestCFG018_LoopbackAndAbsent_NoFinding(t *testing.T) {
	f := CFG018.Check(settingsTarget(t, `{"mcpServers":{"c":{"command":"s","env":{"HOST":"127.0.0.1"}}}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding for loopback, got %+v", f)
	}
	if f := CFG018.Check(settingsTarget(t, `{"mcpServers":{"c":{"command":"s"}}}`)); len(f) != 0 {
		t.Errorf("expected no finding when no bind address, got %+v", f)
	}
}

func TestCFG018_NoSettings_NoFinding(t *testing.T) {
	if f := CFG018.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding when no servers present, got %+v", f)
	}
}
