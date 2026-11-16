// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"
)

// A restricted setting written as a flat dotted key below it is reported like
// the other spellings, and the message names CVE-2026-121661 instead of the
// nested-form CVEs (#1806).
func TestCFG048_DottedBelow1806(t *testing.T) {
	for _, tc := range []struct {
		name, js, want, notWant string
	}{
		{"terminal profile path",
			`{"terminal.integrated.profiles.linux.build.path": "./tools/shell.sh"}`,
			"installed shell. This value is written as a flat dotted key below the setting, which VS Code 1.145.2 and earlier", "nested-object form"},
		{"terminal env",
			`{"terminal.integrated.env.linux.BASH_ENV": "./scripts/env.sh"}`,
			"Remove it. This value is written as a flat dotted key below the setting", "nested-object form"},
		{"nested form keeps its note",
			`{"terminal": {"integrated": {"profiles": {"linux": {"build": {"path": "./tools/shell.sh"}}}}}}`,
			"installed shell. This value is written in nested-object form", "CVE-2026-121661"},
		{"flat setting has no note",
			`{"terminal.integrated.profiles.linux": {"build": {"path": "./tools/shell.sh"}}}`,
			"Point the profile at an installed shell", "This value is written"},
	} {
		f := CFG048.Check(vscodeSettingsTarget(t, tc.js))
		if len(f) != 1 {
			t.Fatalf("%s: want one finding, got %+v", tc.name, f)
		}
		if !strings.Contains(f[0].Message, tc.want) || strings.Contains(f[0].Message, tc.notWant) {
			t.Errorf("%s: want %q and not %q in %q", tc.name, tc.want, tc.notWant, f[0].Message)
		}
	}
}

// VS Code splits a dotted key on every ".", so a pattern with a dot in it does
// not survive below the setting: "/.*/" lands under "/" and "*/", which is no
// catch-all, and nothing is reported.
func TestCFG048_DottedBelowSplitPattern1806(t *testing.T) {
	if f := CFG048.Check(vscodeSettingsTarget(t, `{"chat.tools.terminal.autoApprove./.*/": true}`)); len(f) != 0 {
		t.Errorf("want no finding, got %+v", f)
	}
}

func TestEndNote1806(t *testing.T) {
	if got := endNote("Remove it", ""); got != "Remove it" {
		t.Errorf("no note: %q", got)
	}
	if got := endNote("Remove it", " Note."); got != "Remove it. Note." {
		t.Errorf("note: %q", got)
	}
}
