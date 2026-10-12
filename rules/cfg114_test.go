package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func TestCFG114_PluginAndTool(t *testing.T) {
	for kind, when := range map[string]string{"plugin": "every time OpenCode starts", "tool": "as soon as OpenCode loads an agent"} {
		f := CFG114.Check(&Target{Scope: finding.ScopeProject, AgentCode: &AgentCodeFile{Path: ".opencode/" + kind + "/x.ts", Kind: kind}})
		if len(f) != 1 || f[0].Severity != finding.Error || f[0].File != ".opencode/"+kind+"/x.ts" {
			t.Fatalf("%s: expected one error on the file, got %+v", kind, f)
		}
		if !strings.Contains(f[0].Message, when) || !strings.Contains(f[0].Message, "no workspace trust step") {
			t.Errorf("%s: message does not say when it runs: %s", kind, f[0].Message)
		}
	}
	if f := CFG114.Check(&Target{}); len(f) != 0 {
		t.Errorf("no OpenCode code file, no finding: %+v", f)
	}
}

// An agent file's permission frontmatter is judged like the same block in
// opencode.json, order included (#642).
func TestCFG105_AgentFrontmatterPermission(t *testing.T) {
	grant := parser.OpenCodeAgentPermission("---\npermission:\n  external_directory:\n    \"*\": allow\n---\nbody\n")
	f := CFG105.Check(&Target{Scope: finding.ScopeProject, OpenCode: &parser.OpenCodeConfig{Agent: map[string]parser.OpenCodeAgent{"a": {Permission: grant}}}, OpenCodeFile: ".opencode/agent/a.md"})
	if len(f) != 1 || f[0].File != ".opencode/agent/a.md" || !strings.HasPrefix(f[0].Message, "agent.a.permission ") {
		t.Fatalf("expected one CFG105 finding on the agent file, got %+v", f)
	}
	// A later ask wins by last match, so re-asking after a blanket allow is fine.
	ordered := parser.OpenCodeAgentPermission("---\npermission:\n  read:\n    \"*\": allow\n    \"*.env\": ask\n    \"*.env.*\": ask\n---\n")
	if f := CFG105.Check(&Target{OpenCode: &parser.OpenCodeConfig{Permission: ordered}, OpenCodeFile: "a.md"}); len(f) != 0 {
		t.Errorf("a later ask restores the .env prompt, expected no finding, got %+v", f)
	}
}
