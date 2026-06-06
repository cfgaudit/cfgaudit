package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

// fakeInlineKey is a realistic-length literal built at runtime so gosec G101
// does not flag the test itself for a hardcoded credential.
var fakeInlineKey = "sk-proj-" + strings.Repeat("A", 20)

func continueTarget(cc *parser.ContinueConfig) *Target {
	return &Target{Scope: finding.ScopeProject, Continue: cc, ContinueFile: ".continue/config.yaml"}
}

func TestCFG065_ModelAPIKey_Error(t *testing.T) {
	cc := &parser.ContinueConfig{Models: []parser.ContinueModel{
		{Name: "gpt", Provider: "openai", APIKey: fakeInlineKey},
	}}
	f := CFG065.Check(continueTarget(cc))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error for hardcoded model apiKey, got %+v", f)
	}
}

func TestCFG065_RemoteMCPAPIKey_Error(t *testing.T) {
	cc := &parser.ContinueConfig{MCPServers: []parser.ContinueMCP{
		{Name: "remote", URL: "https://mcp.example", APIKey: fakeInlineKey},
	}}
	if f := CFG065.Check(continueTarget(cc)); len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error for hardcoded mcp apiKey, got %+v", f)
	}
}

func TestCFG065_ReferencesAndPlaceholders_NoFinding(t *testing.T) {
	for _, key := range []string{
		"${{ secrets.OPENAI_API_KEY }}",
		"${OPENAI_API_KEY}",
		"YOUR_API_KEY",
		"sk-...",
		"<your-key-here>",
		"changeme",
		"",
		"short",
	} {
		cc := &parser.ContinueConfig{Models: []parser.ContinueModel{{Name: "m", APIKey: key}}}
		if f := CFG065.Check(continueTarget(cc)); len(f) != 0 {
			t.Errorf("expected no finding for apiKey %q, got %+v", key, f)
		}
	}
	if f := CFG065.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding for non-Continue target, got %+v", f)
	}
}
