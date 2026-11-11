// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A self-looping skill link is absent to every agent, so the scan stays
// complete and exit 0, while cfgaudit names the link on stderr (#1694).
func TestLoopingLinkIsAbsent1694(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs symlinks")
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".agents"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("skills", filepath.Join(dir, ".agents", "skills")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "AGENTS.md"), []byte("real\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runCLI(t, "--claude-version", "2.1.0", "--format", "text", dir)
	if code != 0 {
		t.Fatalf("want exit 0, got %d, stderr:\n%s", code, errOut)
	}
	if !strings.Contains(errOut, "symbolic link loops and was skipped as absent") ||
		!strings.Contains(errOut, filepath.Join(dir, ".agents", "skills")) {
		t.Errorf("want the looping link named as skipped, got %s", errOut)
	}

}

// A two-link loop under .claude/skills is named as two skipped links.
func TestLoopingTwoLinks1694(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs symlinks")
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".claude", "skills"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("b", filepath.Join(dir, ".claude", "skills", "a")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a", filepath.Join(dir, ".claude", "skills", "b")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "CLAUDE.md"), []byte("real\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runCLI(t, "--claude-version", "2.1.0", "--format", "text", dir)
	if code != 0 {
		t.Fatalf("want exit 0, got %d, stderr:\n%s", code, errOut)
	}
	if !strings.Contains(errOut, "2 symbolic links loop and were skipped as absent") {
		t.Errorf("want both links named as skipped, got %s", errOut)
	}
}
