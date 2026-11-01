// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// An allow entry that the same file's deny list fully blocks has no effect,
// since Claude Code checks deny first, and is not reported (#1041). A partial
// overlap still is.
func TestAllowCoveredByDeny(t *testing.T) {
	for _, tc := range []struct {
		rule        Rule
		allow, deny string
		reported    bool
	}{
		// CFG001
		{CFG001, `"Bash"`, `"Bash"`, false},
		{CFG001, `"Bash(*)"`, `"Bash"`, false},
		{CFG001, `"Bash"`, `"Bash(*)"`, false},
		{CFG001, `"PowerShell"`, `"PowerShell"`, false},
		{CFG001, `"Bash"`, `"Bash(rm:*)"`, true},
		{CFG001, `"Bash"`, `"PowerShell"`, true},
		// CFG023
		{CFG023, `"Bash(curl:*)"`, `"Bash(curl:*)"`, false},
		{CFG023, `"Bash(curl https://x.example:*)"`, `"Bash(curl:*)"`, false},
		{CFG023, `"Bash(sudo:*)"`, `"Bash"`, false},
		{CFG023, `"Bash(curl:*)"`, `"Bash(curl https://x.example:*)"`, true},
		{CFG023, `"Bash(curl:*)"`, `"Read(.env)"`, true},
		// CFG002
		{CFG002, `"Edit(*)"`, `"Edit"`, false},
		{CFG002, `"Write"`, `"Write"`, false},
		{CFG002, `"Edit"`, `"Edit(.env)"`, true},
		// CFG040
		{CFG040, `"WebFetch"`, `"WebFetch"`, false},
		{CFG040, `"WebFetch(domain:*)"`, `"WebFetch(domain:*)"`, false},
		{CFG040, `"WebFetch"`, `"WebFetch(domain:evil.example)"`, true},
	} {
		tg := settingsTarget(t, `{"permissions":{"allow":[`+tc.allow+`],"deny":[`+tc.deny+`]}}`)
		tg.Scope = finding.ScopeProject
		got := len(tc.rule.Check(tg)) > 0
		if got != tc.reported {
			t.Errorf("%s allow %s deny %s: reported=%v, want %v", tc.rule.ID(), tc.allow, tc.deny, got, tc.reported)
		}
	}
}

// A deny list in a file Claude Code discards whole blocks nothing, so the
// allow entry is still reported.
func TestAllowCoveredByDeny_DiscardedFile(t *testing.T) {
	tg := settingsTarget(t, `{"permissions":{"allow":["Bash"],"deny":["Bash"]},"env":"x"}`)
	if !tg.discarded() {
		t.Fatal("fixture is no longer discarded; pick another type mismatch")
	}
	if f := CFG001.Check(tg); len(f) == 0 {
		t.Error("expected CFG001: the deny list of a discarded file is not in force")
	}
}
