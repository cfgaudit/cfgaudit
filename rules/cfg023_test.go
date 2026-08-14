package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG023_NetworkAndPrivilege_Error(t *testing.T) {
	for _, entry := range []string{"Bash(curl *)", "Bash(wget *)", "Bash(sudo *)", "Bash(npx *)", "Bash(bash -c *)"} {
		json := `{"permissions":{"allow":["` + entry + `"]}}`
		f := CFG023.Check(settingsTarget(t, json))
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("expected 1 Error for %s, got %+v", entry, f)
		}
	}
}

func TestCFG023_ColonWildcardSyntax(t *testing.T) {
	f := CFG023.Check(settingsTarget(t, `{"permissions":{"allow":["Bash(curl:*)"]}}`))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error for Bash(curl:*), got %+v", f)
	}
	if !strings.Contains(f[0].Message, "curl") {
		t.Errorf("expected message to name curl, got: %s", f[0].Message)
	}
}

func TestCFG023_ExecViaFlags_Warn(t *testing.T) {
	for _, entry := range []string{"Bash(find *)", "Bash(sed *)", "Bash(awk *)", "Bash(tar *)", "Bash(env *)"} {
		json := `{"permissions":{"allow":["` + entry + `"]}}`
		f := CFG023.Check(settingsTarget(t, json))
		if len(f) != 1 || f[0].Severity != finding.Warn {
			t.Errorf("expected 1 Warn for %s, got %+v", entry, f)
		}
	}
}

// A git allow entry that pins a subcommand without an exec vector of its own is
// exempt: git's flag vector needs the position before the subcommand, which the
// pin puts out of reach (#224, #507). State-changing subcommands count too — the
// question is exec capability, not whether the repository is written to.
func TestCFG023_GitNonExecSubcmd_NoFinding(t *testing.T) {
	for _, entry := range []string{
		"Bash(git status:*)", "Bash(git diff:*)", "Bash(git log:*)",
		"Bash(git rev-parse:*)", "Bash(git show *)", "Bash(git blame:*)",
		"Bash(git add:*)", "Bash(git commit:*)", "Bash(git branch:*)",
		"Bash(git checkout:*)", "Bash(git tag:*)", "Bash(git stash:*)",
		"Bash(git restore:*)", "Bash(git merge:*)", "Bash(git worktree *)",
	} {
		json := `{"permissions":{"allow":["` + entry + `"]}}`
		if f := CFG023.Check(settingsTarget(t, json)); len(f) != 0 {
			t.Errorf("expected no finding for non-exec git %s, got %+v", entry, f)
		}
	}
}

// Every entry here reaches arbitrary command execution: the first three leave the
// pre-subcommand flag position open, the rest pin a subcommand that carries a
// vector in its own arguments.
func TestCFG023_GitDangerousForms_Warn(t *testing.T) {
	for _, entry := range []string{
		"Bash(git *)", "Bash(git:*)", "Bash(git -c core.pager=x status:*)",
		"Bash(git config:*)", "Bash(git push:*)", "Bash(git rebase:*)",
		"Bash(git bisect:*)", "Bash(git submodule *)", "Bash(git clone:*)",
		"Bash(git difftool:*)", "Bash(git grep:*)", "Bash(git ls-remote:*)",
		"Bash(git filter-branch:*)", "Bash(git archive:*)", "Bash(git fetch:*)",
	} {
		json := `{"permissions":{"allow":["` + entry + `"]}}`
		f := CFG023.Check(settingsTarget(t, json))
		if len(f) != 1 || f[0].Severity != finding.Warn {
			t.Errorf("expected 1 Warn for %s, got %+v", entry, f)
		}
	}
}

// A pinned subcommand is named as such in the message, and the reason states the
// vector that subcommand actually has rather than git's generic flag vector.
func TestCFG023_GitPinnedSubcmdMessageNamesVector(t *testing.T) {
	f := CFG023.Check(settingsTarget(t, `{"permissions":{"allow":["Bash(git rebase:*)"]}}`))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for Bash(git rebase:*), got %+v", f)
	}
	for _, want := range []string{`"git rebase"`, "git rebase -x"} {
		if !strings.Contains(f[0].Message, want) {
			t.Errorf("expected message to contain %q, got: %s", want, f[0].Message)
		}
	}
	if strings.Contains(f[0].Message, "core.pager") {
		t.Errorf("pinned subcommand must not be reported with git's pre-subcommand flag vector: %s", f[0].Message)
	}
}

func TestCFG023_ExactCommand_NoFinding(t *testing.T) {
	// No wildcard => the user pinned the exact command; exempt even for risky binaries.
	for _, entry := range []string{"Bash(git status)", "Bash(curl https://api.example/health)", "Bash(npm test)"} {
		json := `{"permissions":{"allow":["` + entry + `"]}}`
		if f := CFG023.Check(settingsTarget(t, json)); len(f) != 0 {
			t.Errorf("expected no finding for exact command %s, got %+v", entry, f)
		}
	}
}

func TestCFG023_StandardToolingNotFlagged(t *testing.T) {
	for _, entry := range []string{"Bash(make *)", "Bash(npm run *)", "Bash(go build ./...)", "Bash(pip install *)", "Bash(docker *)"} {
		json := `{"permissions":{"allow":["` + entry + `"]}}`
		if f := CFG023.Check(settingsTarget(t, json)); len(f) != 0 {
			t.Errorf("expected no finding for standard tooling %s, got %+v", entry, f)
		}
	}
}

func TestCFG023_FullWildcardLeftToCFG001(t *testing.T) {
	// Bash(*) is CFG001's job; CFG023 must not also fire on it.
	if f := CFG023.Check(settingsTarget(t, `{"permissions":{"allow":["Bash(*)"]}}`)); len(f) != 0 {
		t.Errorf("expected no CFG023 finding for Bash(*), got %+v", f)
	}
}

// Bash(command:curl *) uses the 2.1.178 param form on the canonicalized `command`
// field, which Claude Code ignores (startup warning, grants nothing). The inner
// token parses to "command" — not a dangerous binary — so CFG023 does not flag it,
// matching Claude's behaviour. The dangerous grant must use Bash's own specifier
// (Bash(curl *) / Bash(curl:*)), which TestCFG023_ColonWildcardSyntax covers.
func TestCFG023_CommandParamForm_NotFlagged(t *testing.T) {
	for _, entry := range []string{"Bash(command:curl *)", "Bash(command:sudo *)"} {
		json := `{"permissions":{"allow":["` + entry + `"]}}`
		if f := CFG023.Check(settingsTarget(t, json)); len(f) != 0 {
			t.Errorf("expected no finding for ignored param-form %q, got %+v", entry, f)
		}
	}
}

func TestCFG023_NonBashEntries_NoFinding(t *testing.T) {
	f := CFG023.Check(settingsTarget(t, `{"permissions":{"allow":["Edit(src/*)","Read(*)","WebFetch(*)"]}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding for non-Bash entries, got %+v", f)
	}
}

func TestCFG023_NoPermissions_NoFinding(t *testing.T) {
	if f := CFG023.Check(settingsTarget(t, `{"env":{"X":"y"}}`)); len(f) != 0 {
		t.Errorf("expected no finding without permissions, got %+v", f)
	}
}

func TestCFG023_WindowsLOLBinsAndShells(t *testing.T) {
	for _, entry := range []string{"Bash(certutil *)", "Bash(bitsadmin *)", "Bash(mshta *)", "Bash(regsvr32 *)", "Bash(rundll32 *)", "Bash(powershell *)", "Bash(pwsh *)", "Bash(cmd *)"} {
		json := `{"permissions":{"allow":["` + entry + `"]}}`
		f := CFG023.Check(settingsTarget(t, json))
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("expected 1 Error for %s, got %+v", entry, f)
		}
	}
}
