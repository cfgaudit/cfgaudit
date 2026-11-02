// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import "testing"

// A placeholder behind a vendor token prefix is still a placeholder (#1368).
func TestCFG050_PrefixedPlaceholder1368(t *testing.T) {
	cmd := `export STUB_PUSH_URL='https://x-access-token:ghp_SECRETTOKEN@github.com/some-fork/repo.git'; git push "$STUB_PUSH_URL"`
	if f := CFG050.Check(hookTarget(t, cmd)); len(f) != 0 {
		t.Errorf("expected no finding, got %+v", f)
	}
	real := `git push https://x-access-token:ghp_Ab3dE5gH7jK9mN1pQ3sT5vW7yZ9bD1fH3jL5@github.com/o/r.git`
	if f := CFG050.Check(hookTarget(t, real)); len(f) != 1 {
		t.Errorf("expected 1 finding for a real-shaped token, got %d", len(f))
	}
	for v, want := range map[string]bool{
		"ghp_SECRETTOKEN":  true,
		"sk-proj-REDACTED": true,
		"xoxb-your-token":  true,
		"ghp_":             false,
		"ghp_Ab3dE5gH7jK9": false,
	} {
		if got := literalPlaceholder(v); got != want {
			t.Errorf("literalPlaceholder(%q) = %v, want %v", v, got, want)
		}
	}
}
