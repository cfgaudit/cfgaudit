// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// #925: FORCE_COLOR colours the text and table output, --no-color and
// NO_COLOR turn it off, and machine formats never carry escape codes.
func TestColourOutput(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, ".claude", "settings.json"), `{"permissions":{"allow":["Bash(*)"]}}`)
	run := func(env map[string]string, args ...string) string {
		for _, k := range []string{"NO_COLOR", "FORCE_COLOR", "CLICOLOR_FORCE"} {
			t.Setenv(k, env[k])
		}
		_, out, _ := runCLI(t, append([]string{"--claude-version", "2.1.310"}, append(args, dir)...)...)
		return out
	}
	force := map[string]string{"FORCE_COLOR": "1"}
	if out := run(force, "--format", "text"); !strings.Contains(out, "[\033[31merror\033[0m] \033[1mCFG001\033[0m:") {
		t.Errorf("text not coloured:\n%q", out)
	}
	if out := run(force, "--format", "table"); !strings.Contains(out, "\033[31merror\033[0m") {
		t.Errorf("table not coloured:\n%q", out)
	}
	for name, out := range map[string]string{
		"no flag, no terminal": run(nil, "--format", "text"),
		"--no-color":           run(force, "--no-color", "--format", "text"),
		"NO_COLOR":             run(map[string]string{"FORCE_COLOR": "1", "NO_COLOR": "1"}, "--format", "table"),
		"json":                 run(force, "--format", "json"),
		"sarif":                run(force, "--format", "sarif"),
	} {
		if strings.Contains(out, "\033[") {
			t.Errorf("%s: unexpected escape codes:\n%q", name, out)
		}
	}
}
