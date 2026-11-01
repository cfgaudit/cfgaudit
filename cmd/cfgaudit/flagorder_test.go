// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// Flags after the directory take effect, and a second path is an error
// instead of being ignored (#1047). Each row of the issue.
func TestRun_FlagsAfterDirectory(t *testing.T) {
	root := runFixture(t, map[string]string{".claude/settings.json": warnSettings})
	cv := "--claude-version=2.1.316"

	if _, out, _ := runCLI(t, root, cv, "--format", "sarif"); !strings.Contains(out, `"version": "2.1.0"`) {
		t.Errorf("--format sarif after the directory: not SARIF:\n%.200s", out)
	}
	if code, _, _ := runCLI(t, cv, root); code != 0 {
		t.Fatalf("baseline: warn findings only should exit 0, got %d", code)
	}
	if code, _, _ := runCLI(t, root, cv, "--strict"); code != 1 {
		t.Errorf("--strict after the directory: exit %d, want 1", code)
	}
	if _, out, _ := runCLI(t, root, cv, "--format", "json", "--only", "CFG006"); strings.Contains(out, "CFG040") || !strings.Contains(out, "CFG006") {
		t.Errorf("--only CFG006 after the directory: got %s", out)
	}

	other := t.TempDir()
	for _, args := range [][]string{
		{cv, root, other},
		{cv, root, filepath.Join(root, "does-not-exist")},
		{root, cv, other, "--strict"},
	} {
		code, _, errOut := runCLI(t, args...)
		if code != 2 || !strings.Contains(errOut, "cfgaudit: expected at most one directory, got 2:") {
			t.Errorf("%q: exit %d, stderr %q", args, code, errOut)
		}
	}
}

// "--" ends flag parsing: a directory that starts with a dash can follow it,
// and a flag after it is a path, not a flag.
func TestRun_DoubleDashEndsFlags(t *testing.T) {
	root := runFixture(t, map[string]string{"-dir/.claude/settings.json": errorSettings})
	dashed := filepath.Join(root, "-dir")
	if code, _, errOut := runCLI(t, "--claude-version=2.1.316", "--strict", "--", dashed); code != 1 {
		t.Errorf("-- <dir>: exit %d, want 1 (warn findings under --strict)\n%s", code, errOut)
	}
	code, _, errOut := runCLI(t, "--claude-version=2.1.316", root, "--", "--strict")
	if code != 2 || !strings.Contains(errOut, "expected at most one directory, got 2: "+root+" --strict") {
		t.Errorf("<dir> -- --strict: exit %d, stderr %q", code, errOut)
	}
}
