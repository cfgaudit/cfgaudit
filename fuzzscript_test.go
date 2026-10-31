// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package cfgaudit

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// The fuzz job passes when go test failed only because the fuzz time ran out
// with no failing input written, and fails on anything else (#1135).
func TestFuzzScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fuzz job runs on the Linux runner")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not installed")
	}
	script, err := filepath.Abs(filepath.Join(".github", "scripts", "fuzz.sh"))
	if err != nil {
		t.Fatal(err)
	}

	deadline := "fuzz: elapsed: 46s, execs: 31451 (0/sec)\n--- FAIL: FuzzX (46.23s)\n    context deadline exceeded\nFAIL\nexit status 1\n"
	for _, tc := range []struct {
		name   string
		output string
		exit   int
		write  bool // the stub writes a failing input
		wantOK bool
	}{
		{name: "pass", output: "ok\n", exit: 0, wantOK: true},
		{name: "deadline only", output: deadline, exit: 1, wantOK: true},
		{name: "deadline with a written input", output: deadline, exit: 1, write: true},
		{name: "panic", output: "--- FAIL: FuzzX (2.00s)\n    --- FAIL: FuzzX (0.00s)\n        testing.go:1: panic: boom\n    Failing input written to testdata/fuzz/FuzzX/abc\nFAIL\n", exit: 1, write: true},
		{name: "deadline among other lines", output: "--- FAIL: FuzzX (46.23s)\n    context deadline exceeded\n    fuzzing process hung or terminated unexpectedly\nFAIL\n", exit: 1},
		{name: "another target", output: "--- FAIL: FuzzY (46.23s)\n    something else\n--- FAIL: FuzzX (46.23s)\n    context deadline exceeded\nFAIL\n", exit: 1, wantOK: true},
		{name: "build error", output: "# pkg\n./x.go:1: syntax error\nFAIL\tpkg [build failed]\n", exit: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(dir, "pkg", "testdata", "fuzz", "FuzzX"), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "pkg", "testdata", "fuzz", "FuzzX", "seed"), []byte("go test fuzz v1\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "out"), []byte(tc.output), 0o600); err != nil {
				t.Fatal(err)
			}
			stub := "#!/usr/bin/env bash\ncat out\n"
			if tc.write {
				stub += "echo x > pkg/testdata/fuzz/FuzzX/abc\n"
			}
			stub += "exit " + strconv.Itoa(tc.exit) + "\n"
			if err := os.WriteFile(filepath.Join(dir, "go"), []byte(stub), 0o700); err != nil { //nolint:gosec // G306: the stub must be executable
				t.Fatal(err)
			}
			cmd := exec.Command("bash", script, "./pkg", "FuzzX", "45s") //nolint:gosec // G204: fixed binary, arguments from the test
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "GO="+filepath.Join(dir, "go"))
			out, err := cmd.CombinedOutput()
			if gotOK := err == nil; gotOK != tc.wantOK {
				t.Fatalf("passed = %v, want %v\n%s", gotOK, tc.wantOK, out)
			}
			if tc.wantOK && tc.exit != 0 && !strings.Contains(string(out), "::warning") {
				t.Errorf("no warning annotation:\n%s", out)
			}
		})
	}
}
