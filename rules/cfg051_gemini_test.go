// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// #1153: Gemini CLI does not read allowed-tools, so a skill under
// .gemini/skills is not reported; the same file under .claude/skills is.
func TestCFG051_GeminiSkills1153(t *testing.T) {
	const content = "---\nname: x\ndescription: Do x.\nallowed-tools: Bash\n---\nBody.\n"
	for path, want := range map[string]int{
		".gemini/skills/x/SKILL.md":              0,
		"/home/u/.gemini/skills/x/SKILL.md":      0,
		`C:\Users\u\.gemini\skills\x\SKILL.md`:   0,
		".claude/skills/x/SKILL.md":              1,
		".qwen/skills/x/SKILL.md":                1,
		"docs/.gemini/skills-overview/README.md": 1,
	} {
		f := CFG051.Check(&Target{Scope: finding.ScopeProject, InstructionFile: path, InstructionContent: content})
		if len(f) != want {
			t.Errorf("%s: want %d findings, got %+v", path, want, f)
		}
	}
}
