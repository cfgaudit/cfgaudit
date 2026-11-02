// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func instructionTarget(file, content string) *Target {
	return &Target{Scope: finding.ScopeProject, InstructionFile: file, InstructionContent: content}
}

func TestCFG051_BroadGrants(t *testing.T) {
	cases := []struct {
		name, fm, want string
		sev            finding.Severity
	}{
		// Total access → error.
		{"all-star", "allowed-tools: \"*\"", "all tools", finding.Error},
		{"all-word", "allowed-tools: all", "all tools", finding.Error},
		// Unrestricted shell → warn (broad but commonly legitimate).
		{"bare-bash", "allowed-tools: Bash, Read", "unrestricted shell", finding.Warn},
		{"bash-list", "allowed-tools:\n  - Bash\n  - Read", "unrestricted shell", finding.Warn},
		// Claude Code matches tool names case-sensitively: measured on
		// 2.1.316, bash, shell and execute let no Bash call through (#1196).
		{"shell", "allowed-tools: shell", "grants nothing", finding.Info},
		{"lower-bash", "allowed-tools: bash", "grants nothing", finding.Info},
	}
	for _, c := range cases {
		content := "---\ndescription: x\n" + c.fm + "\n---\nbody\n"
		f := CFG051.Check(instructionTarget(".claude/commands/c.md", content))
		if len(f) != 1 || f[0].Severity != c.sev || !strings.Contains(f[0].Message, c.want) {
			t.Errorf("%s: expected %s containing %q, got %+v", c.name, c.sev, c.want, f)
		}
	}
}

func TestCFG051_ScalarToolSpecs(t *testing.T) {
	cases := []struct {
		name, fm string
		sev      finding.Severity
	}{
		{"scoped-nx", "allowed-tools: Bash(pnpm exec nx:*)", ""},
		{"scoped-git", "allowed-tools: Bash(git -C * status)", ""},
		{"scoped-list", "allowed-tools: Read, Bash(git log *), Bash(gh pr edit * --add-label *)", ""},
		{"bare-bash", "allowed-tools: Read Bash", finding.Warn},
		{"bash-star", "allowed-tools: Bash(*)", finding.Warn},
		{"all-list", "allowed-tools: [\"*\"]", finding.Error},
		{"scoped-and-all", "allowed-tools: Bash(git log *), *", finding.Error},
		{"unclosed-scope", "allowed-tools: Bash(git log, *", finding.Error},
		{"spaced-bash-star", "allowed-tools: Bash( * )", finding.Warn},
		{"bash-double-star", "allowed-tools: Bash(**)", finding.Warn},
		{"bash-spaced-stars", "allowed-tools: Bash(* *)", finding.Warn},
		{"exec-spaced-stars", "allowed-tools: Exec(* *)", finding.Warn},
		{"bash-three-stars", "allowed-tools: Bash(* * *)", finding.Warn},
		{"bash-colon-pattern", "allowed-tools: Bash(*:*)", ""},
		{"bash-git-pattern", "allowed-tools: Bash(git *)", ""},
		{"all-with-unclosed-deny", "allowed-tools: \"*\"\ndisallowed-tools: Bash(rm *", finding.Error},
		{"bash-with-scalar-denies", "allowed-tools: Bash\ndisallowed-tools: Read, Bash", ""},
		{"all-with-scoped-deny", "allowed-tools: \"*\"\ndisallowed-tools: Bash(rm *)", finding.Error},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			content := "---\ndescription: x\n" + c.fm + "\n---\nbody\n"
			f := CFG051.Check(&Target{InstructionFile: ".claude/skills/deploy/SKILL.md", InstructionContent: content})
			wantCount := 0
			if c.sev != "" {
				wantCount = 1
			}
			if len(f) != wantCount {
				t.Fatalf("expected %d findings, got %+v", wantCount, f)
			}
			if len(f) == 1 && f[0].Severity != c.sev {
				t.Errorf("expected severity %s, got %s", c.sev, f[0].Severity)
			}
		})
	}
}

func TestCFG051_DisallowedCancels(t *testing.T) {
	content := "---\ndescription: x\nallowed-tools: Bash, Read\ndisallowed-tools: Bash\n---\nbody\n"
	if f := CFG051.Check(instructionTarget(".claude/commands/c.md", content)); len(f) != 0 {
		t.Errorf("expected no finding when disallowed-tools cancels Bash, got %+v", f)
	}
}

func TestCFG051_NotFlagged(t *testing.T) {
	cases := []string{
		"---\ndescription: x\nallowed-tools: Bash(npm test), Read\n---\nbody\n", // scoped Bash
		"---\ndescription: x\nallowed-tools: Read, Edit\n---\nbody\n",           // specific tools
		"---\ndescription: x\n---\nbody\n",                                      // no allowed-tools
		"# CLAUDE.md\n\nNo frontmatter here.\n",                                 // not a frontmatter file
	}
	for _, c := range cases {
		if f := CFG051.Check(instructionTarget(".claude/commands/c.md", c)); len(f) != 0 {
			t.Errorf("expected no finding for %q, got %+v", c, f)
		}
	}
}

func TestCFG051_NamesFile(t *testing.T) {
	f := CFG051.Check(instructionTarget(".claude/agents/helper.md", "---\nallowed-tools: \"*\"\n---\nx\n"))
	if len(f) != 1 || f[0].File != ".claude/agents/helper.md" || !strings.Contains(f[0].Message, "helper.md") {
		t.Fatalf("expected finding naming helper.md, got %+v", f)
	}
}

func TestCFG051_NoContent_NoFinding(t *testing.T) {
	if f := CFG051.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding for empty target, got %+v", f)
	}
}

// Devin's command tool is "exec"; on a skill, allowed-tools auto-approves it.
// On a Devin subagent profile allowed-tools restricts instead, so it is not a
// grant to report (#644).
func TestCFG051_DevinExec(t *testing.T) {
	skill := &Target{InstructionFile: ".devin/skills/deploy/SKILL.md", InstructionContent: "---\nname: deploy\nallowed-tools:\n  - read\n  - exec\n---\nbody\n"}
	if f := CFG051.Check(skill); len(f) != 1 || f[0].Severity != finding.Warn || !strings.Contains(f[0].Message, `"exec"`) || !strings.Contains(f[0].Message, "Exec(npm test)") {
		t.Fatalf("expected a warn for exec, got %+v", f)
	}
	profile := &Target{InstructionFile: "repo/.devin/agents/runner.md", InstructionContent: "---\nname: runner\nallowed-tools:\n  - exec\n---\nbody\n"}
	if f := CFG051.Check(profile); len(f) != 0 {
		t.Errorf("a Devin agent profile's allowed-tools restricts, expected no finding, got %+v", f)
	}
}

// Skill roots by measured reader (#1196): roots only Copilot CLI or OpenCode
// read are not reported, roots with unmeasured readers are info, and a Claude
// Code root keeps the warning.
func TestCFG051_SkillRoots1196(t *testing.T) {
	content := "---\nname: release\nallowed-tools: Bash\n---\nbody\n"
	for path, want := range map[string]string{
		".claude/skills/release/SKILL.md":   "warn",
		".github/skills/release/SKILL.md":   "",
		".opencode/skills/release/SKILL.md": "",
		".opencode/skill/release/SKILL.md":  "",
		".agents/skills/release/SKILL.md":   "info",
		".codex/skills/release/SKILL.md":    "info",
		".cursor/skills/release/SKILL.md":   "info",
		"my-plugin/skills/release/SKILL.md": "warn",
	} {
		f := CFG051.Check(instructionTarget(path, content))
		got := ""
		if len(f) == 1 {
			got = string(f[0].Severity)
		} else if len(f) > 1 {
			got = "many"
		}
		if got != want {
			t.Errorf("%s: got %q, want %q (%+v)", path, got, want, f)
		}
	}
}
