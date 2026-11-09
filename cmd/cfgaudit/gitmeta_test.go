// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
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
	if len(got) != 3 || !got["fixtures/evil.git/config error"] || !got[".gitmodules warn"] || !got[".git/config error"] {
		t.Errorf("got %v", got)
	}
	if ts := gitTargets(t.TempDir()); ts != nil {
		t.Errorf("empty dir: %+v", ts)
	}
}

// The scanned folder's own .git/config is read, in a folder scan only, and
// nested .git directories are left alone (#1408).
func TestGitTargets_ProjectConfig(t *testing.T) {
	cfg := "[core]\n\tfsmonitor = ./scripts/write-marker\n"
	root := runFixture(t, map[string]string{".git/config": cfg, "sub/.git/config": cfg})
	code, out, _ := runCLI(t, "--only", "CFG121", "--format", "text", root)
	if code != 1 || strings.Count(out, "CFG121") != 1 || !strings.Contains(out, filepath.Join(".git", "config")) {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if strings.Contains(out, "write-marker") {
		t.Fatalf("value in the output:\n%s", out)
	}

	root = runFixture(t, map[string]string{".git/config": "[remote \"origin\"]\n\turl = https://example.invalid/repo.git\n"})
	if code, out, _ := runCLI(t, "--only", "CFG121", "--format", "text", root); code != 0 || strings.Contains(out, "CFG121") {
		t.Fatalf("clone-style config: exit %d:\n%s", code, out)
	}
}

// An archive's .git is CFG122's finding, not CFG121's as well.
func TestGitTargets_ArchiveNotDoubled(t *testing.T) {
	p := filepath.Join(t.TempDir(), "t.zip")
	writeZip(t, p, []archEntry{{name: ".git/config", body: "[core]\n\tfsmonitor = ./x\n"}})
	var out, errb bytes.Buffer
	code := run([]string{"cfgaudit", "--config", os.DevNull, "--only", "CFG121,CFG122", "--format", "text", p}, nil, &out, &errb)
	if code != 1 || strings.Contains(out.String(), "CFG121") || !strings.Contains(out.String(), "CFG122") {
		t.Fatalf("exit %d:\n%s\n%s", code, out.String(), errb.String())
	}
}
