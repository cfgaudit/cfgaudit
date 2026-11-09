// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"testing"
)

// Root tool binaries, venvs and yarnPath reach CFG123 (#997).
func TestStandins997(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "git.exe"), "MZ")
	mustWrite(t, filepath.Join(dir, ".venv", "pyvenv.cfg"), "home = /usr/bin\n")
	mustWrite(t, filepath.Join(dir, ".yarnrc.yml"), "nodeLinker: node-modules\nyarnPath: \"scripts/run-yarn.js\"\n")
	got := map[string]bool{}
	for _, f := range scanFindings(t, "--only", "CFG123", dir) {
		rel, _ := filepath.Rel(dir, f.File)
		got[filepath.ToSlash(rel)] = true
	}
	if len(got) != 3 || !got["git.exe"] || !got[".venv/pyvenv.cfg"] || !got[".yarnrc.yml"] {
		t.Errorf("got %v", got)
	}
	if ts := standinTargets(filepath.Join(dir, "missing")); ts != nil {
		t.Errorf("missing dir: %+v", ts)
	}
}
