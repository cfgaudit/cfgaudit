package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func policyTarget(t *testing.T, settingsJSON string, requireDeny, forbidAllow []string) *Target {
	tg := settingsTarget(t, settingsJSON)
	tg.Scope = finding.ScopeProject
	tg.PolicyRequireDeny = requireDeny
	tg.PolicyForbidAllow = forbidAllow
	return tg
}

func TestCFG025_RequireDeny_NotDenied_Fires(t *testing.T) {
	tg := policyTarget(t, `{"permissions":{"deny":["Read(.env)"]}}`, []string{"Bash(git commit:*)"}, nil)
	f := CFG025.Check(tg)
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error (git commit not denied), got %+v", f)
	}
}

func TestCFG025_RequireDeny_CoveredByBroaderDeny_OK(t *testing.T) {
	for _, deny := range []string{"Bash(git commit:*)", "Bash(git:*)", "Bash(*)"} {
		tg := policyTarget(t, `{"permissions":{"deny":["`+deny+`"]}}`, []string{"Bash(git commit:*)"}, nil)
		if f := CFG025.Check(tg); len(f) != 0 {
			t.Errorf("deny %q should satisfy require-deny, got %+v", deny, f)
		}
	}
}

func TestCFG025_RequireDeny_NarrowerDeny_Fires(t *testing.T) {
	// denying only "git commit --amend" does not block "git commit" in general
	tg := policyTarget(t, `{"permissions":{"deny":["Bash(git commit --amend)"]}}`, []string{"Bash(git commit:*)"}, nil)
	if f := CFG025.Check(tg); len(f) != 1 {
		t.Fatalf("expected finding (narrower deny doesn't cover), got %+v", f)
	}
}

func TestCFG025_ForbidAllow_GrantedByBroaderAllow_Fires(t *testing.T) {
	for _, allow := range []string{"Bash(git:*)", "Bash(git commit:*)", "Bash(*)", "Bash(git commit --amend)"} {
		tg := policyTarget(t, `{"permissions":{"allow":["`+allow+`"]}}`, nil, []string{"Bash(git commit:*)"})
		f := CFG025.Check(tg)
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("allow %q should violate forbid-allow, got %+v", allow, f)
		}
		if len(f) == 1 && !strings.Contains(f[0].Message, allow) {
			t.Errorf("message should name the granting entry %q, got %s", allow, f[0].Message)
		}
	}
}

func TestCFG025_ForbidAllow_UnrelatedAllow_OK(t *testing.T) {
	tg := policyTarget(t, `{"permissions":{"allow":["Bash(git status:*)","Bash(npm run *)"]}}`, nil, []string{"Bash(git commit:*)"})
	if f := CFG025.Check(tg); len(f) != 0 {
		t.Errorf("unrelated allow entries should not violate forbid-allow, got %+v", f)
	}
}

func TestCFG025_ToolMismatch_OK(t *testing.T) {
	tg := policyTarget(t, `{"permissions":{"allow":["Edit(*)","Read(*)"]}}`, nil, []string{"Bash(git commit:*)"})
	if f := CFG025.Check(tg); len(f) != 0 {
		t.Errorf("non-Bash allow must not match a Bash forbid-allow, got %+v", f)
	}
}

func TestCFG025_NoPolicy_Inert(t *testing.T) {
	tg := settingsTarget(t, `{"permissions":{"allow":["Bash(*)"]}}`)
	if f := CFG025.Check(tg); len(f) != 0 {
		t.Errorf("expected no findings without a policy, got %+v", f)
	}
}

func TestCFG025_NoSettings_RequireDenyStillFires(t *testing.T) {
	// A project with a policy but no deny at all: the command is not denied.
	tg := &Target{Scope: finding.ScopeProject, SettingsFile: ".claude/settings.json", PolicyRequireDeny: []string{"Bash(git push:*)"}}
	if f := CFG025.Check(tg); len(f) != 1 {
		t.Fatalf("expected require-deny to fire when nothing is denied, got %+v", f)
	}
}
