// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// pyc returns a .pyc header for Python 3.12 (magic 3531) with the flags word.
func pyc(flags byte) string {
	return string([]byte{0xcb, 0x0d, '\r', '\n', flags, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8})
}

const (
	pycTimestamp = 0
	pycUnchecked = 1
	pycChecked   = 3
)

func bytecodeFindings(t *testing.T, dir string) map[string]finding.Severity {
	t.Helper()
	got := map[string]finding.Severity{}
	for _, f := range scanFindings(t, "--only", "CFG129", dir) {
		rel, _ := filepath.Rel(dir, f.File)
		got[filepath.ToSlash(rel)] = f.Severity
	}
	return got
}

// The table of #1398, measured with CPython 3.12.
func TestBytecode1398(t *testing.T) {
	dir := t.TempDir()
	write := func(p, c string) { mustWrite(t, filepath.Join(dir, filepath.FromSlash(p)), c) }
	write("s/helper.py", "print('source')\n")
	write("s/__pycache__/helper.cpython-312.pyc", pyc(pycUnchecked))
	write("s/ok.py", "")
	write("s/__pycache__/ok.cpython-312.pyc", pyc(pycTimestamp))
	write("s/chk.py", "")
	write("s/__pycache__/chk.cpython-312.opt-1.pyc", pyc(pycChecked))
	write("s/__pycache__/stale.cpython-312.pyc", pyc(pycTimestamp))
	write("s/__pycache__/gone.cpython-312.pyc", pyc(pycUnchecked))
	write("s/lone.pyc", pyc(pycTimestamp))
	write("s/both.py", "")
	write("s/both.pyc", pyc(pycUnchecked))
	write("s/notpyc.pyc", "plain text, not bytecode")
	write("s/short.pyc", "ab")
	write("s/py2.pyc", string([]byte{0x03, 0xf3, '\r', '\n', 1, 0, 0, 0}))
	write("node_modules/x/lone.pyc", pyc(pycUnchecked))
	got := bytecodeFindings(t, dir)
	want := map[string]finding.Severity{
		"s/__pycache__/helper.cpython-312.pyc": finding.Error,
		"s/__pycache__/gone.cpython-312.pyc":   finding.Warn,
		"s/lone.pyc":                           finding.Warn,
	}
	if len(got) != len(want) {
		t.Errorf("got %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q, want %q", k, got[k], v)
		}
	}
	if ts := bytecodeTargets(filepath.Join(dir, "missing")); ts != nil {
		t.Errorf("missing dir: %+v", ts)
	}
	if _, ok := pycHeader(filepath.Join(dir, "missing.pyc")); ok {
		t.Error("a missing file has no header")
	}
}

// In a git checkout only a tracked file is committed.
func TestBytecodeTracked1398(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "a.py"), "")
	mustWrite(t, filepath.Join(dir, "__pycache__", "a.cpython-312.pyc"), pyc(pycUnchecked))
	mustWrite(t, filepath.Join(dir, "__pycache__", "b.cpython-312.pyc"), pyc(pycUnchecked))
	mustWrite(t, filepath.Join(dir, "gone.pyc"), pyc(pycTimestamp))
	for _, args := range [][]string{{"init", "-q"}, {"add", "a.py", "gone.pyc", "__pycache__/a.cpython-312.pyc"}} {
		cmd := exec.Command("git", args...) // #nosec G204 -- fixed arguments
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	if err := os.Remove(filepath.Join(dir, "gone.pyc")); err != nil {
		t.Fatal(err)
	}
	got := bytecodeFindings(t, dir)
	if len(got) != 1 || got["__pycache__/a.cpython-312.pyc"] != finding.Error {
		t.Errorf("got %v", got)
	}
}
