// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// A defaultMode the detected Claude Code ignores in a project file does not
// raise the credential-coverage rules or CFG006 (#1660); CFG004 already calls
// it inert there.
func TestCredentialRules_IgnoredModeDoesNotEscalate_1660(t *testing.T) {
	const fixture = `{"permissions":{"defaultMode":"auto","deny":["Bash(bun tsc:*)"]}}`
	rules := []Rule{CFG041, CFG042, CFG043, CFG044}

	check := func(ver string, want finding.Severity) {
		t.Helper()
		for _, r := range rules {
			f := r.Check(scopedSettingsTarget(t, fixture, finding.ScopeProject, ver))
			if len(f) == 0 {
				t.Fatalf("%s at %s: no finding", r.ID(), ver)
			}
			for _, x := range f {
				if x.Severity != want {
					t.Errorf("%s at %s: severity %s, want %s: %s", r.ID(), ver, x.Severity, want, x.Message)
				}
			}
		}
	}
	// 2.1.322 ignores a project-scope auto mode: none of these deny lists
	// guards a secret, so each is a warning.
	check("2.1.322", finding.Warn)
	// 2.1.250 still honours it: the deny list is the only gate, an error.
	check("2.1.250", finding.Error)
	// No version detected: the mode keeps its honoured reading.
	check("", finding.Error)
}

func TestCredentialRules_BypassIgnoredInProjectScope_1660(t *testing.T) {
	const fixture = `{"permissions":{"defaultMode":"bypassPermissions","deny":["Bash(bun tsc:*)"]}}`
	for _, r := range []Rule{CFG041, CFG042, CFG043, CFG044} {
		for _, x := range r.Check(scopedSettingsTarget(t, fixture, finding.ScopeProject, "2.1.322")) {
			if x.Severity != finding.Warn {
				t.Errorf("%s: severity %s, want warn: %s", r.ID(), x.Severity, x.Message)
			}
		}
		// The user scope is not repo-controlled: the mode applies.
		for _, x := range r.Check(scopedSettingsTarget(t, fixture, finding.ScopeUser, "2.1.322")) {
			if x.Severity != finding.Error {
				t.Errorf("%s user scope: severity %s, want error: %s", r.ID(), x.Severity, x.Message)
			}
		}
	}
}

// With a bare Bash allow and a .env guard, the deny list does guard secrets,
// so a class it leaves open (keys and certificates, CFG042) stays an error
// without any help from the ignored mode.
func TestCredentialRules_BareBashStillError_1660(t *testing.T) {
	const fixture = `{"permissions":{"defaultMode":"auto","allow":["Bash"],"deny":["Read(./.env)"]}}`
	f := CFG042.Check(scopedSettingsTarget(t, fixture, finding.ScopeProject, "2.1.322"))
	if len(f) == 0 {
		t.Fatal("CFG042: no finding")
	}
	for _, x := range f {
		if x.Severity != finding.Error {
			t.Errorf("CFG042: severity %s, want error: %s", x.Severity, x.Message)
		}
	}
}

func TestCFG006_IgnoredModeIsNotPermissive_1660(t *testing.T) {
	const fixture = `{"permissions":{"defaultMode":"auto"}}`
	if f := CFG006.Check(scopedSettingsTarget(t, fixture, finding.ScopeProject, "2.1.322")); len(f) != 0 {
		t.Errorf("2.1.322 ignores the mode: want no CFG006, got %v", f)
	}
	if f := CFG006.Check(scopedSettingsTarget(t, fixture, finding.ScopeProject, "2.1.250")); len(f) != 1 {
		t.Errorf("2.1.250 honours the mode: want 1 CFG006, got %v", f)
	}
}
