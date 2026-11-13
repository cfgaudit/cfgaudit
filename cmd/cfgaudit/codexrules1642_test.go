// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"reflect"
	"testing"
)

// CFG140 reads each project .codex/rules file without a policy (#1642).
func TestCFG140_EndToEnd(t *testing.T) {
	root := runFixture(t, map[string]string{
		".codex/rules/default.rules": `prefix_rule(pattern=["git", "push"], decision="forbidden")` + "\n",
		".codex/rules/canon.rules":   `prefix_rule(pattern=["rm"], decision="forbidden", canonical_matching=True)` + "\n",
		".codex/rules/notes.txt":     `prefix_rule(pattern=["x"], decision="forbidden")`,
	})
	got := launchedFindings(t, root, "CFG140")
	want := []string{"CFG140 info .codex/rules/canon.rules", "CFG140 info .codex/rules/default.rules"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}
