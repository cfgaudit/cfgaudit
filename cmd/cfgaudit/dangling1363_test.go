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

// A dangling symlink is absent to every agent, so it does not fail the scan;
// an unreadable file still does (#1363).
func TestDanglingLinkIsAbsent1363(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs symlinks")
	}
	dir := t.TempDir()
	if err := os.Symlink("AGENTS.md", filepath.Join(dir, "CLAUDE.md")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".github"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../docs/agents.md", filepath.Join(dir, ".github", "copilot-instructions.md")); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runCLI(t, "--config", os.DevNull, "--claude-version", "2.1.316", "--format", "json", dir)
	if code != 0 || strings.Contains(out, `"RuleID"`) {
		t.Errorf("want exit 0 and no finding, got %d, %s", code, out)
	}
	if !strings.Contains(errOut, "2 symbolic links point to a missing file and were skipped as absent") ||
		!strings.Contains(errOut, "CLAUDE.md") || !strings.Contains(errOut, "copilot-instructions.md") || strings.Contains(errOut, "could not read") {
		t.Errorf("want both links named as skipped, got %s", errOut)
	}

	if os.Geteuid() == 0 {
		return // root reads everything
	}
	locked := filepath.Join(dir, "AGENTS.md")
	mustWrite(t, filepath.Join(dir, "docs", "agents.md"), "# Agents\n")
	mustWrite(t, locked, "# Agents\n")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o600) })
	if err := os.Remove(filepath.Join(dir, ".github", "copilot-instructions.md")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../missing.md", filepath.Join(dir, ".github", "copilot-instructions.md")); err != nil {
		t.Fatal(err)
	}
	code, _, errOut = runCLI(t, "--config", os.DevNull, "--claude-version", "2.1.316", "--format", "json", dir)
	if code != 2 || !strings.Contains(errOut, "could not read 2 paths") || !strings.Contains(errOut, "1 symbolic link points to a missing file") {
		t.Errorf("want exit 2 for AGENTS.md and the CLAUDE.md link to it, and the missing link named as skipped, got %d, %s", code, errOut)
	}
}
