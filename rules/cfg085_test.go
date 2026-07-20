package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func agentTarget(mode string) *Target {
	fm := "---\nname: helper\ndescription: does things\n"
	if mode != "" {
		fm += "permissionMode: " + mode + "\n"
	}
	fm += "---\n\nBody text.\n"
	return &Target{
		Scope:              finding.ScopeProject,
		InstructionFile:    ".claude/agents/helper.md",
		InstructionContent: fm,
	}
}

func TestCFG085_WeakeningModes(t *testing.T) {
	cases := map[string]finding.Severity{
		"bypassPermissions": finding.Error,
		"dontAsk":           finding.Error,
		"auto":              finding.Warn,
		"acceptEdits":       finding.Warn,
	}
	for mode, want := range cases {
		f := CFG085.Check(agentTarget(mode))
		if len(f) != 1 || f[0].Severity != want {
			t.Errorf("expected 1 %s for permissionMode %q, got %+v", want, mode, f)
		}
	}
}

// default, plan and manual prompt normally, and manual is documented as an alias
// for default — none of them weakens anything.
func TestCFG085_SafeModes_NoFinding(t *testing.T) {
	for _, mode := range []string{"default", "plan", "manual", ""} {
		if f := CFG085.Check(agentTarget(mode)); len(f) != 0 {
			t.Errorf("expected no finding for permissionMode %q, got %+v", mode, f)
		}
	}
}

// The field only means something in a subagent definition. Claude Code documents
// that it is ignored for plugin subagents, and it is inert in a CLAUDE.md or a
// skill, so firing there would be a false positive.
func TestCFG085_WrongSurface_NoFinding(t *testing.T) {
	body := "---\nname: x\ndescription: d\npermissionMode: bypassPermissions\n---\nbody\n"
	for _, path := range []string{
		"CLAUDE.md",
		".claude/skills/x/SKILL.md",
		".claude/commands/x.md",
		"plugins/foo/agents/helper.md", // plugin tree, not .claude/agents
		".cursorrules",
	} {
		tgt := &Target{Scope: finding.ScopeProject, InstructionFile: path, InstructionContent: body}
		if f := CFG085.Check(tgt); len(f) != 0 {
			t.Errorf("expected no finding for %s, got %+v", path, f)
		}
	}
}

func TestCFG085_UserScopeAgent(t *testing.T) {
	tgt := agentTarget("bypassPermissions")
	tgt.InstructionFile = "/home/u/.claude/agents/helper.md"
	if f := CFG085.Check(tgt); len(f) != 1 {
		t.Errorf("expected the finding for a user-scope agent file, got %+v", f)
	}
}

func TestCFG085_NoFrontmatter_NoFinding(t *testing.T) {
	tgt := &Target{Scope: finding.ScopeProject, InstructionFile: ".claude/agents/helper.md", InstructionContent: "no frontmatter here\n"}
	if f := CFG085.Check(tgt); len(f) != 0 {
		t.Errorf("expected no finding without frontmatter, got %+v", f)
	}
}

func TestCFG085_NoTarget_NoFinding(t *testing.T) {
	if f := CFG085.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding for an empty target, got %+v", f)
	}
}
