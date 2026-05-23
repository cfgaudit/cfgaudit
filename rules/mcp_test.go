package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func mcpJSONTarget(servers map[string]parser.MCPServer) *Target {
	return &Target{
		SettingsFile:   ".claude/settings.json",
		Scope:          finding.ScopeProject,
		ProjectMCP:     servers,
		ProjectMCPFile: ".mcp.json",
	}
}

func TestCFG010_FiresOnProjectMCPJSON(t *testing.T) {
	tgt := mcpJSONTarget(map[string]parser.MCPServer{
		"fs": {Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-filesystem@latest", "/tmp"}},
	})
	f := CFG010.Check(tgt)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for unpinned .mcp.json server, got %d", len(f))
	}
	if f[0].File != ".mcp.json" {
		t.Errorf("expected finding attributed to .mcp.json, got %q", f[0].File)
	}
}

func TestCFG011_FiresOnProjectMCPJSON(t *testing.T) {
	tgt := mcpJSONTarget(map[string]parser.MCPServer{
		"db": {Command: "/bin/db", AlwaysAllow: []string{"*"}},
	})
	f := CFG011.Check(tgt)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for wildcard alwaysAllow in .mcp.json, got %d", len(f))
	}
	if f[0].File != ".mcp.json" {
		t.Errorf("expected finding attributed to .mcp.json, got %q", f[0].File)
	}
}

func TestMCPRefs_CoversBothSourcesWithCorrectFiles(t *testing.T) {
	// A server inline in settings.json and another in .mcp.json must both be
	// scanned, each attributed to its own file.
	tgt := settingsTarget(t, `{"mcpServers":{"inline":{"command":"npx","args":["pkg@latest"]}}}`)
	tgt.Scope = finding.ScopeProject
	tgt.ProjectMCP = map[string]parser.MCPServer{
		"fromfile": {Command: "npx", Args: []string{"other@latest"}},
	}
	tgt.ProjectMCPFile = ".mcp.json"

	f := CFG010.Check(tgt)
	if len(f) != 2 {
		t.Fatalf("expected findings for both sources, got %d: %+v", len(f), f)
	}
	files := map[string]bool{}
	for _, fi := range f {
		files[fi.File] = true
	}
	if !files["test/settings.json"] || !files[".mcp.json"] {
		t.Errorf("expected one finding per source file, got files %v", files)
	}
}

func TestMCPRefs_NilTarget(t *testing.T) {
	var tgt *Target
	if refs := tgt.mcpServerRefs(); refs != nil {
		t.Errorf("expected nil refs for nil target, got %+v", refs)
	}
}

func TestMCPRefs_NoServers(t *testing.T) {
	if refs := (&Target{}).mcpServerRefs(); refs != nil {
		t.Errorf("expected nil refs when no servers present, got %+v", refs)
	}
}
