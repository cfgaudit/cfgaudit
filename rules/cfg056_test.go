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

func TestCFG056_GreedyTriggersField(t *testing.T) {
	// A scoped description but a greedy entry in the triggers list must flag,
	// and the message must name the triggers field, not the description.
	f := CFG056.Check(fmTarget(".claude/skills/s/SKILL.md",
		"Deploy the app to staging when asked",
		"triggers:\n  - deploy to staging\n  - before every request\n"))
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 warn for a greedy triggers entry, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "triggers") {
		t.Errorf("expected the message to name the triggers field, got %q", f[0].Message)
	}
}

func TestCFG056_GreedyTriggersScalar(t *testing.T) {
	// triggers given as a comma-separated scalar — phrases must stay intact.
	f := CFG056.Check(fmTarget(".claude/skills/s/SKILL.md",
		"Review the diff", "triggers: review the diff, on any user message\n"))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for a greedy scalar triggers, got %+v", f)
	}
}

func TestCFG056_GreedyTriggers_NoDescription(t *testing.T) {
	// No description, but a greedy triggers entry — must still flag (the empty
	// description must not short-circuit the triggers scan).
	f := CFG056.Check(fmTarget(".claude/skills/s/SKILL.md", "",
		"triggers:\n  - always invoke this\n"))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for greedy triggers with no description, got %+v", f)
	}
}

func TestCFG056_ScopedTriggers_NoFinding(t *testing.T) {
	for _, trig := range []string{
		"triggers:\n  - deploy the app\n  - release to staging\n",
		"triggers: format staged files, summarize the CI run\n",
	} {
		if f := CFG056.Check(fmTarget(".claude/skills/s/SKILL.md", "Deploy the app", trig)); len(f) != 0 {
			t.Errorf("expected no finding for scoped triggers %q, got %+v", trig, f)
		}
	}
}

func TestCFG056_NamesFile(t *testing.T) {
	f := CFG056.Check(fmTarget(".claude/agents/helper.md", "Always use this", ""))
	if len(f) != 1 || f[0].File != ".claude/agents/helper.md" || !strings.Contains(f[0].Message, "helper.md") {
		t.Fatalf("expected finding naming helper.md, got %+v", f)
	}
}
