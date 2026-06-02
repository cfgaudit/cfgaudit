package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func fmTarget(file, description string, extra string) *Target {
	content := "---\ndescription: " + description + "\n" + extra + "---\nbody\n"
	return &Target{Scope: finding.ScopeProject, InstructionFile: file, InstructionContent: content}
}

func TestCFG056_GreedyTriggers(t *testing.T) {
	for _, desc := range []string{
		"Use this for every request, no matter what the user asks",
		"Always invoke this agent before each task",
		"Run this regardless of the task at hand",
		"Apply to all requests",
		"Use it for everything",
		"Trigger before every prompt",
		"Relevant in all situations",
	} {
		f := CFG056.Check(fmTarget(".claude/commands/c.md", desc, ""))
		if len(f) != 1 || f[0].Severity != finding.Warn {
			t.Errorf("expected warn for %q, got %+v", desc, f)
		}
	}
}

func TestCFG056_ScopedDescriptions_NoFinding(t *testing.T) {
	for _, desc := range []string{
		"Deploy the app to staging when the user asks about deployment",
		"Review the current diff for security issues",
		"Handles any task related to database migrations",
		"Format all staged files with prettier",
		"Summarize the latest CI run",
	} {
		if f := CFG056.Check(fmTarget(".claude/commands/c.md", desc, "")); len(f) != 0 {
			t.Errorf("expected no finding for scoped %q, got %+v", desc, f)
		}
	}
}

func TestCFG056_DisableModelInvocation_Exempt(t *testing.T) {
	f := CFG056.Check(fmTarget(".claude/commands/c.md", "Use this for everything", "disable-model-invocation: true\n"))
	if len(f) != 0 {
		t.Errorf("expected no finding when disable-model-invocation is true, got %+v", f)
	}
}

func TestCFG056_NoFrontmatterOrDescription_NoFinding(t *testing.T) {
	cases := []*Target{
		{Scope: finding.ScopeProject, InstructionFile: "CLAUDE.md", InstructionContent: "# CLAUDE.md\n\nUse this for every request.\n"}, // body prose, no frontmatter
		{Scope: finding.ScopeProject, InstructionFile: "c.md", InstructionContent: "---\nname: x\n---\nbody\n"},                         // frontmatter, no description
		{},
	}
	for _, tg := range cases {
		if f := CFG056.Check(tg); len(f) != 0 {
			t.Errorf("expected no finding, got %+v", f)
		}
	}
}

func TestCFG056_NamesFile(t *testing.T) {
	f := CFG056.Check(fmTarget(".claude/agents/helper.md", "Always use this", ""))
	if len(f) != 1 || f[0].File != ".claude/agents/helper.md" || !strings.Contains(f[0].Message, "helper.md") {
		t.Fatalf("expected finding naming helper.md, got %+v", f)
	}
}
