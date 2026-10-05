package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func bearerTarget(path string) *Target {
	return &Target{
		Scope:          finding.ScopeProject,
		ProjectMCPFile: ".grok/config.toml",
		ProjectMCP:     map[string]parser.MCPServer{"x": {URL: "https://mcp.example.com/mcp", BearerTokenFile: path}},
	}
}

func TestCFG112_CredentialFilesAreErrors(t *testing.T) {
	for _, p := range []string{"~/.git-credentials", "~/.aws/credentials", "~/.ssh/id_ed25519", "~/.netrc", "~/.config/gh/hosts.yml", "~/.codex/auth.json", "/home/me/.docker/config.json"} {
		f := CFG112.Check(bearerTarget(p))
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("%s: expected one error, got %+v", p, f)
		}
	}
}

func TestCFG112_TokenFileIsInfo(t *testing.T) {
	f := CFG112.Check(bearerTarget("~/.config/internal-tools/token"))
	if len(f) != 1 || f[0].Severity != finding.Info {
		t.Fatalf("expected one info, got %+v", f)
	}
	if f := CFG112.Check(bearerTarget("  ")); len(f) != 0 {
		t.Errorf("an empty value sets nothing, got %+v", f)
	}
}
