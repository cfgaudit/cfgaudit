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
	for _, entry := range []string{"Bash(find *)", "Bash(sed *)", "Bash(awk *)", "Bash(tar *)", "Bash(git *)", "Bash(env *)"} {
		json := `{"permissions":{"allow":["` + entry + `"]}}`
		f := CFG023.Check(settingsTarget(t, json))
		if len(f) != 1 || f[0].Severity != finding.Warn {
			t.Errorf("expected 1 Warn for %s, got %+v", entry, f)
		}
	}
}

// A git allow entry pinned to a read-only subcommand is exempt (#224), but the
// unscoped/flag-injection/state-changing forms still warn.
func TestCFG023_GitReadOnlySubcmd_NoFinding(t *testing.T) {
	for _, entry := range []string{
		"Bash(git status:*)", "Bash(git diff:*)", "Bash(git log:*)",
		"Bash(git rev-parse:*)", "Bash(git show *)", "Bash(git blame:*)",
	} {
		json := `{"permissions":{"allow":["` + entry + `"]}}`
		if f := CFG023.Check(settingsTarget(t, json)); len(f) != 0 {
			t.Errorf("expected no finding for read-only git %s, got %+v", entry, f)
		}
	}
}

func TestCFG023_GitDangerousForms_Warn(t *testing.T) {
	for _, entry := range []string{
		"Bash(git *)", "Bash(git:*)", "Bash(git -c core.pager=x status:*)",
		"Bash(git config:*)", "Bash(git push:*)",
	} {
		json := `{"permissions":{"allow":["` + entry + `"]}}`
		f := CFG023.Check(settingsTarget(t, json))
		if len(f) != 1 || f[0].Severity != finding.Warn {
			t.Errorf("expected 1 Warn for %s, got %+v", entry, f)
		}
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
