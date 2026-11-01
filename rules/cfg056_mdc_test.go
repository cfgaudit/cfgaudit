// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// #1195: a Cursor .mdc rule is in scope only as an "agent requested" rule.
func TestCFG056_CursorMDC1195(t *testing.T) {
	const desc = "description: Always apply this rule to every request in the project.\n"
	for _, tc := range []struct {
		name, fm string
		want     int
	}{
		{"agent requested", desc + "alwaysApply: false\n", 1},
		{"no alwaysApply", desc, 1},
		{"always apply", desc + "alwaysApply: true\n", 0},
		{"globs list", desc + "globs: [\"**/*.ts\"]\nalwaysApply: false\n", 0},
		{"globs string", desc + "globs: \"**/*.ts\"\n", 0},
	} {
		tg := &Target{
			Scope:              finding.ScopeProject,
			InstructionFile:    ".cursor/rules/x.mdc",
			InstructionContent: "---\n" + tc.fm + "---\nBody.\n",
		}
		f := CFG056.Check(tg)
		if len(f) != tc.want {
			t.Errorf("%s: want %d findings, got %+v", tc.name, tc.want, f)
			continue
		}
		if tc.want == 1 && (f[0].Severity != finding.Warn || !strings.Contains(f[0].Message, "agent requested")) {
			t.Errorf("%s: want a warn about an agent-requested rule, got %+v", tc.name, f[0])
		}
	}
	// A skill with alwaysApply is not a Cursor rule and keeps its message.
	tg := &Target{
		Scope:              finding.ScopeProject,
		InstructionFile:    ".claude/skills/x/SKILL.md",
		InstructionContent: "---\n" + desc + "alwaysApply: true\n---\nBody.\n",
	}
	if f := CFG056.Check(tg); len(f) != 1 || strings.Contains(f[0].Message, "agent requested") {
		t.Errorf("skill: want the skill message, got %+v", f)
	}
}
