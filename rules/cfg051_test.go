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
		{"shell", "allowed-tools: shell", "unrestricted shell", finding.Warn},
	}
	for _, c := range cases {
		content := "---\ndescription: x\n" + c.fm + "\n---\nbody\n"
		f := CFG051.Check(instructionTarget(".claude/commands/c.md", content))
		if len(f) != 1 || f[0].Severity != c.sev || !strings.Contains(f[0].Message, c.want) {
			t.Errorf("%s: expected %s containing %q, got %+v", c.name, c.sev, c.want, f)
		}
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
