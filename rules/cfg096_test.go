package rules

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func mcpTrustTarget(file string, trust bool) *Target {
	return &Target{
		Scope:          finding.ScopeProject,
		ProjectMCPFile: file,
		ProjectMCP:     map[string]parser.MCPServer{"internal": {URL: "https://mcp.example.test/mcp", Trust: trust}},
	}
}

// Both committable Gemini surfaces can declare the flag.
func TestCFG096_GeminiSources(t *testing.T) {
	for _, file := range []string{
		filepath.Join(".gemini", "settings.json"),
		filepath.Join(".gemini", "agents", "helper.md"),
		filepath.Join("/repo", ".gemini", "agents", "helper.md"),
	} {
		t.Run(file, func(t *testing.T) {
			f := CFG096.Check(mcpTrustTarget(file, true))
			if len(f) != 1 || f[0].Severity != finding.Error {
				t.Fatalf("expected 1 Error, got %+v", f)
			}
			if !strings.Contains(f[0].Message, "trust: true") {
				t.Errorf("message should name the flag, got %q", f[0].Message)
			}
			// The mitigation is real and must be stated, not glossed.
			if !strings.Contains(f[0].Message, "folder is trusted") {
				t.Errorf("message should name the folder-trust condition, got %q", f[0].Message)
			}
		})
	}
}

// Only Gemini declares the key. Elsewhere it is inert, so reporting it would be
// a false positive.
func TestCFG096_NonGeminiSourcesSilent(t *testing.T) {
	for _, file := range []string{
		".mcp.json",
		filepath.Join(".cursor", "mcp.json"),
		filepath.Join(".vscode", "mcp.json"),
		filepath.Join(".claude", "agents", "x.md"),
		filepath.Join(".qwen", "settings.json"), // fork, but unverified: deliberately out
		"",
	} {
		t.Run("file="+file, func(t *testing.T) {
			if f := CFG096.Check(mcpTrustTarget(file, true)); len(f) != 0 {
				t.Errorf("expected no findings for %q, got %+v", file, f)
			}
		})
	}
}

func TestCFG096_NoTrustSilent(t *testing.T) {
	if f := CFG096.Check(mcpTrustTarget(filepath.Join(".gemini", "settings.json"), false)); len(f) != 0 {
		t.Errorf("expected no findings without trust, got %+v", f)
	}
	if f := CFG096.Check(nil); len(f) != 0 {
		t.Errorf("expected no findings for a nil target, got %+v", f)
	}
	if f := CFG096.Check(&Target{Scope: finding.ScopeProject}); len(f) != 0 {
		t.Errorf("expected no findings without MCP servers, got %+v", f)
	}
}
