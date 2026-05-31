package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

// settings.json mcpServers + .mcp.json declaring the same name → one warn naming both.
func TestCFG052_Collision(t *testing.T) {
	tg := settingsTarget(t, `{"mcpServers":{"github":{"command":"npx"},"unique":{"command":"npx"}}}`)
	tg.ProjectMCPFile = ".mcp.json"
	tg.ProjectMCP = map[string]parser.MCPServer{"github": {Command: "node"}, "other": {Command: "npx"}}

	f := CFG052.Check(tg)
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 warn, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "mcpServers.github") ||
		!strings.Contains(f[0].Message, "test/settings.json") || !strings.Contains(f[0].Message, ".mcp.json") {
		t.Errorf("expected message naming github and both sources, got: %s", f[0].Message)
	}
}

func TestCFG052_DistinctNames_NoFinding(t *testing.T) {
	tg := settingsTarget(t, `{"mcpServers":{"a":{"command":"npx"}}}`)
	tg.ProjectMCPFile = ".mcp.json"
	tg.ProjectMCP = map[string]parser.MCPServer{"b": {Command: "npx"}}
	if f := CFG052.Check(tg); len(f) != 0 {
		t.Errorf("expected no finding for distinct names, got %+v", f)
	}
}

func TestCFG052_SingleSource_NoFinding(t *testing.T) {
	// Two servers, both only in .mcp.json — no cross-source collision.
	tg := &Target{
		Scope:          finding.ScopeProject,
		ProjectMCPFile: ".mcp.json",
		ProjectMCP:     map[string]parser.MCPServer{"a": {Command: "npx"}, "b": {Command: "npx"}},
	}
	if f := CFG052.Check(tg); len(f) != 0 {
		t.Errorf("expected no finding within a single source, got %+v", f)
	}
}

func TestCFG052_MultipleCollisions_SortedOnePerName(t *testing.T) {
	tg := settingsTarget(t, `{"mcpServers":{"zeta":{"command":"x"},"alpha":{"command":"x"}}}`)
	tg.ProjectMCPFile = ".mcp.json"
	tg.ProjectMCP = map[string]parser.MCPServer{"zeta": {Command: "y"}, "alpha": {Command: "y"}}
	f := CFG052.Check(tg)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(f))
	}
	// deterministic, sorted by name: alpha before zeta
	if !strings.Contains(f[0].Message, "alpha") || !strings.Contains(f[1].Message, "zeta") {
		t.Errorf("expected sorted findings (alpha, zeta), got %q / %q", f[0].Message, f[1].Message)
	}
}

func TestCFG052_NoMCP_NoFinding(t *testing.T) {
	if f := CFG052.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding without MCP servers, got %+v", f)
	}
}
