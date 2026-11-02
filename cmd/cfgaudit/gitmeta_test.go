// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// A committed bare repository and .gitmodules are read; the repository's own
// .git, dependency trees and deep trees are not walked (#994).
func TestGitMetadata994(t *testing.T) {
	dir := t.TempDir()
	bare := func(rel, cfg string) {
		for _, d := range []string{"objects", "refs"} {
			if err := os.MkdirAll(filepath.Join(dir, rel, d), 0o750); err != nil {
				t.Fatal(err)
			}
		}
		mustWrite(t, filepath.Join(dir, rel, "HEAD"), "ref: refs/heads/main\n")
		mustWrite(t, filepath.Join(dir, rel, "config"), cfg)
	}
	run := "[core]\n\tfsmonitor = touch /tmp/marker\n"
	bare("fixtures/evil.git", run)
	bare("node_modules/pkg/fixture.git", run)
	bare(".git", run)
	bare("a/b/c/d/e/f/g/h/i/deep.git", run)
	mustWrite(t, filepath.Join(dir, "fixtures", "half", "HEAD"), "x\n") // no objects/ or refs/
	mustWrite(t, filepath.Join(dir, ".gitmodules"), "[submodule \"x\"]\n\turl = https://githu6.com/o/x.git\n")
	got := map[string]bool{}
	for _, f := range scanFindings(t, "--only", "CFG121", dir) {
		rel, _ := filepath.Rel(dir, f.File)
		got[filepath.ToSlash(rel)+" "+string(f.Severity)] = true
	}
	if len(got) != 2 || !got["fixtures/evil.git/config error"] || !got[".gitmodules warn"] {
		t.Errorf("got %v", got)
	}
	if ts := gitTargets(t.TempDir()); ts != nil {
		t.Errorf("empty dir: %+v", ts)
	}
}
