// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import "testing"

// A prohibition wrapped across two lines is the same prohibition (#1470).
func TestCFG029_WrappedProhibition1470(t *testing.T) {
	for _, s := range []string{
		"Do not recreate the application from a template or change its framework or\nhosting model without approval.",
		"- Do not recreate the application or change its framework or\n  hosting model without approval.",
		"1. Never change the framework or\n   hosting model without confirmation.",
		"Deploy the docs. Do not change the framework or\nhosting model without approval.",
		"Never\nauto-approve destructive operations.",
	} {
		if f := CFG029.Check(claudeMDTarget(s + "\n")); len(f) != 0 {
			t.Errorf("expected no finding for %q, got %+v", s, f)
		}
	}
}

// The negation does not reach past the end of its sentence or into a line that
// is not part of it.
func TestCFG029_WrappedProhibition1470_StillReported(t *testing.T) {
	for _, s := range []string{
		"Do not delete files.\nDeploy without approval.",
		"Do not delete files.\ndeploy without approval.",
		"Do not delete files;\ndeploy without approval.",
		"Do not delete files\n\ndeploy without approval.",
		"Never push to main:\ndeploy without approval.",
		"# Do not delete files\ndeploy without approval.",
		"- Do not delete files\ndeploy without approval.",
		"- Do not delete files\n- Deploy without approval.",
		"Do not delete files or\nreports. Deploy without approval.",
		"1. **Never deploy unless the user approved that\n   release.** Then run it without confirmation.",
	} {
		if f := CFG029.Check(claudeMDTarget(s + "\n")); len(f) != 1 {
			t.Errorf("expected one finding for %q, got %+v", s, f)
		}
	}
}
