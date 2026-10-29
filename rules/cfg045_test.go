// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG045_DisabledByDefault(t *testing.T) {
	// Without t.ShellCheck the rule must not run (and must not exec anything).
	tg := settingsTarget(t, `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"echo $X"}]}]}}`)
	if f := CFG045.Check(tg); f != nil {
		t.Errorf("expected nil when ShellCheck disabled, got %+v", f)
	}
}

func TestCFG045_NoSettings_NoFinding(t *testing.T) {
	if f := CFG045.Check(&Target{ShellCheck: true}); len(f) != 0 {
		t.Errorf("expected no finding without settings, got %+v", f)
	}
}

func TestParseShellcheck(t *testing.T) {
	out := []byte(`[{"line":2,"column":6,"level":"info","code":2086,"message":"Double quote to prevent globbing and word splitting."}]`)
	cs := parseShellcheck(out)
	if len(cs) != 1 || cs[0].Code != 2086 || cs[0].Level != "info" {
		t.Fatalf("unexpected parse: %+v", cs)
	}
	if parseShellcheck([]byte("not json")) != nil {
		t.Errorf("expected nil for invalid JSON")
	}
}

func TestScSeverity(t *testing.T) {
	cases := map[string]finding.Severity{
		"error":   finding.Error,
		"warning": finding.Warn,
		"info":    finding.Info,
		"style":   finding.Info,
		"weird":   finding.Info,
	}
	for level, want := range cases {
		if got := scSeverity(level); got != want {
			t.Errorf("scSeverity(%q) = %s, want %s", level, got, want)
		}
	}
}

func TestCFG045_HappyPath(t *testing.T) {
	if !ShellcheckAvailable() {
		t.Skip("shellcheck binary not installed")
	}
	tg := settingsTarget(t, `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"rm $FILE"}]}]}}`)
	tg.ShellCheck = true
	f := CFG045.Check(tg)
	if len(f) == 0 {
		t.Fatal("expected shellcheck to flag the unquoted $FILE")
	}
	found := false
	for _, fi := range f {
		if fi.RuleID == "CFG045" && strings.Contains(fi.Message, "SC2086") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an SC2086 finding, got %+v", f)
	}
}

// fakeShellcheck puts a `shellcheck` shell script printing out and exiting
// with code first on PATH, following the fakeClaude pattern in
// internal/version/version_test.go. Shell scripts do not run on Windows, so
// the test skips there.
func fakeShellcheck(t *testing.T, out string, code int) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell")
	}
	dir := t.TempDir()
	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s' '%s'\nexit %d\n", out, code)
	if err := os.WriteFile(filepath.Join(dir, "shellcheck"), []byte(script), 0o700); err != nil { // #nosec G306 -- the test needs an executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
}

// fakeShellcheckRecording is fakeShellcheck, except the script also records
// its arguments to argsFile so the test can assert on the argv it received.
func fakeShellcheckRecording(t *testing.T, argsFile, out string, code int) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell")
	}
	dir := t.TempDir()
	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s' \"$*\" > '%s'\nprintf '%%s' '%s'\nexit %d\n", argsFile, out, code)
	if err := os.WriteFile(filepath.Join(dir, "shellcheck"), []byte(script), 0o700); err != nil { // #nosec G306 -- the test needs an executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
}

func shellcheckTarget(t *testing.T) *Target {
	t.Helper()
	tg := settingsTarget(t, `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"echo $X"}]}]}}`)
	tg.ShellCheck = true
	return tg
}

// A fake shellcheck covers the paths a real binary never takes in CI: a
// non-zero exit with findings (ShellCheck's normal case), a non-zero exit
// with no findings, and output that is not JSON at all.
func TestCFG045_FakeShellcheck(t *testing.T) {
	canned := `[{"line":2,"column":6,"level":"error","code":2086,"message":"Double quote to prevent globbing and word splitting."},{"line":2,"column":1,"level":"warning","code":2034,"message":"X appears unused."}]`
	cases := []struct {
		name     string
		out      string
		code     int
		want     int
		wantSev  []finding.Severity
		wantMsgs []string
	}{
		{name: "findings", out: canned, code: 1, want: 2, wantSev: []finding.Severity{finding.Error, finding.Warn}, wantMsgs: []string{"SC2086", "SC2034"}},
		{name: "exit zero with findings", out: canned, code: 0, want: 2, wantSev: []finding.Severity{finding.Error, finding.Warn}, wantMsgs: []string{"SC2086", "SC2034"}},
		{name: "empty array", out: `[]`, code: 1, want: 0},
		{name: "garbage output", out: `this is not json`, code: 1, want: 0},
		{name: "error with no output", out: ``, code: 1, want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fakeShellcheck(t, tc.out, tc.code)
			f := CFG045.Check(shellcheckTarget(t))
			if len(f) != tc.want {
				t.Fatalf("expected %d findings, got %+v", tc.want, f)
			}
			for i, want := range tc.wantSev {
				if f[i].RuleID != "CFG045" || f[i].Severity != want {
					t.Errorf("finding %d = %+v, want CFG045 with severity %s", i, f[i], want)
				}
			}
			for i, want := range tc.wantMsgs {
				if !strings.Contains(f[i].Message, want) {
					t.Errorf("finding %d message %q does not contain %q", i, f[i].Message, want)
				}
			}
		})
	}
}

// Exclude codes from the config must reach the fake binary's arguments.
func TestCFG045_FakeShellcheckExcludeArgs(t *testing.T) {
	argsFile := filepath.Join(t.TempDir(), "args")
	fakeShellcheckRecording(t, argsFile, `[]`, 1)
	tg := shellcheckTarget(t)
	tg.ShellCheckExclude = []string{"SC2086", "SC2034"}
	if f := CFG045.Check(tg); len(f) != 0 {
		t.Fatalf("expected no findings from the empty array, got %+v", f)
	}
	args, err := os.ReadFile(argsFile) // #nosec G304 -- argsFile is under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(args), "--exclude=SC2086,SC2034") {
		t.Errorf("shellcheck argv = %q, want it to contain --exclude=SC2086,SC2034", string(args))
	}
}

// No shellcheck on PATH at all: the exec error branch of Check must yield no
// findings and no panic, the same way a binary that vanishes mid-run does.
func TestCFG045_ShellcheckMissing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell")
	}
	t.Setenv("PATH", t.TempDir())
	if f := CFG045.Check(shellcheckTarget(t)); len(f) != 0 {
		t.Errorf("expected no findings without a shellcheck binary, got %+v", f)
	}
}

func TestShellcheckArgs(t *testing.T) {
	if got := strings.Join(shellcheckArgs(nil), " "); got != "--shell=bash --format=json -" {
		t.Errorf("args without exclusions = %q", got)
	}
	got := strings.Join(shellcheckArgs([]string{"SC2086", "SC2034"}), " ")
	if got != "--shell=bash --format=json --exclude=SC2086,SC2034 -" {
		t.Errorf("args with exclusions = %q", got)
	}
}

// An excluded code is not reported, and the remaining ones still are: `rm $FILE`
// draws SC2086, `cd /tmp` without a fallback draws SC2164.
func TestCFG045_ExcludedCodeNotReported(t *testing.T) {
	if !ShellcheckAvailable() {
		t.Skip("shellcheck binary not installed")
	}
	tg := settingsTarget(t, `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"cd /tmp; rm $FILE"}]}]}}`)
	tg.ShellCheck = true
	codes := func() string {
		var all []string
		for _, f := range CFG045.Check(tg) {
			all = append(all, f.Message)
		}
		return strings.Join(all, "\n")
	}
	before := codes()
	if !strings.Contains(before, "SC2086") || !strings.Contains(before, "SC2164") {
		t.Fatalf("fixture no longer draws SC2086 and SC2164:\n%s", before)
	}
	tg.ShellCheckExclude = []string{"SC2086"}
	after := codes()
	if strings.Contains(after, "SC2086") {
		t.Errorf("excluded SC2086 still reported:\n%s", after)
	}
	if !strings.Contains(after, "SC2164") {
		t.Errorf("excluding SC2086 also dropped SC2164:\n%s", after)
	}
}
