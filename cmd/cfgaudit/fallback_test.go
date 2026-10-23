// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/version"
)

// captureStderr runs f with os.Stderr swapped for a pipe and returns what f
// wrote, so the warning fallbacks can be asserted.
func captureStderr(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = old })
	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		_, _ = io.Copy(&sb, r)
		done <- sb.String()
	}()
	f()
	_ = w.Close()
	got := <-done
	_ = r.Close()
	return got
}

// fakeBinary puts a shell script named name printing out first on PATH.
// Shell scripts do not run on Windows, so the test skips there.
func fakeBinary(t *testing.T, name, out string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell")
	}
	dir := t.TempDir()
	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s' '%s'\n", out)
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o700); err != nil { // #nosec G306 -- the test needs an executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
}

// An unparseable --claude-version warns and falls back to detection; with no
// claude on PATH the scan runs without version gating (#783).
func TestResolveClaudeVersion_UnparseableFlagNoClaude(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	var got *version.Version
	stderr := captureStderr(t, func() {
		got = resolveClaudeVersion("not-a-version")
	})
	if got != nil {
		t.Errorf("resolveClaudeVersion with no claude on PATH = %v, want nil", got)
	}
	for _, want := range []string{
		`cfgaudit: --claude-version "not-a-version" is not a recognised version; falling back to detection`,
		"cfgaudit: `claude` binary not on PATH; running all rules without version gating",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr = %q, want it to contain %q", stderr, want)
		}
	}
}

// The fallback uses the detected version when a claude binary is on PATH.
func TestResolveClaudeVersion_UnparseableFlagFallsBackToDetected(t *testing.T) {
	fakeBinary(t, "claude", "2.1.150 (Claude Code)")
	var got *version.Version
	stderr := captureStderr(t, func() {
		got = resolveClaudeVersion("not-a-version")
	})
	if got == nil || *got != (version.Version{Major: 2, Minor: 1, Patch: 150}) {
		t.Errorf("resolveClaudeVersion with claude 2.1.150 on PATH = %v, want 2.1.150", got)
	}
	for _, want := range []string{
		`cfgaudit: --claude-version "not-a-version" is not a recognised version; falling back to detection`,
		"cfgaudit: scanning with Claude Code v2.1.150 (detected)",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr = %q, want it to contain %q", stderr, want)
		}
	}
}

// A claude whose --version output does not parse also disables version gating.
func TestResolveClaudeVersion_UnparseableFlagUnparseableDetection(t *testing.T) {
	fakeBinary(t, "claude", "unknown")
	var got *version.Version
	stderr := captureStderr(t, func() {
		got = resolveClaudeVersion("not-a-version")
	})
	if got != nil {
		t.Errorf("resolveClaudeVersion with unparseable claude output = %v, want nil", got)
	}
	if want := "cfgaudit: could not parse `claude --version` output"; !strings.Contains(stderr, want) {
		t.Errorf("stderr = %q, want it to contain %q", stderr, want)
	}
}

// A valid --claude-version wins over detection and does not fall back.
func TestResolveClaudeVersion_ValidFlag(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	var got *version.Version
	stderr := captureStderr(t, func() {
		got = resolveClaudeVersion("2.0.0")
	})
	if got == nil || *got != (version.Version{Major: 2}) {
		t.Errorf("resolveClaudeVersion(\"2.0.0\") = %v, want 2.0.0", got)
	}
	if want := "cfgaudit: scanning with Claude Code v2.0.0 (--claude-version)"; !strings.Contains(stderr, want) {
		t.Errorf("stderr = %q, want it to contain %q", stderr, want)
	}
}

// --shellcheck without a shellcheck binary on PATH warns and runs the scan
// without shell analysis instead of failing it (#783).
func TestShellCheckEnabled_RequestedWithoutBinary(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	var got bool
	stderr := captureStderr(t, func() {
		got = shellCheckEnabled(true)
	})
	if got {
		t.Error("shellCheckEnabled(true) without shellcheck on PATH = true, want false")
	}
	want := "cfgaudit: --shellcheck requested but the shellcheck binary is not on PATH; skipping shell analysis"
	if !strings.Contains(stderr, want) {
		t.Errorf("stderr = %q, want it to contain %q", stderr, want)
	}
}

// With a shellcheck binary on PATH the request is granted silently.
func TestShellCheckEnabled_RequestedWithBinary(t *testing.T) {
	fakeBinary(t, "shellcheck", "")
	var got bool
	stderr := captureStderr(t, func() {
		got = shellCheckEnabled(true)
	})
	if !got {
		t.Error("shellCheckEnabled(true) with shellcheck on PATH = false, want true")
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty", stderr)
	}
}

// Not requesting shell analysis stays silent and off, with or without the
// binary on PATH.
func TestShellCheckEnabled_NotRequested(t *testing.T) {
	var got bool
	stderr := captureStderr(t, func() {
		got = shellCheckEnabled(false)
	})
	if got {
		t.Error("shellCheckEnabled(false) = true, want false")
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty", stderr)
	}
}
