// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG123_Standins997(t *testing.T) {
	tg := &Target{ProjectDir: "/r", RootFiles: []string{"git.exe", "node.cmd", "README.md", "gitx.exe"}, Venvs: []string{".venv"}, YarnPath: "scripts/run-yarn.js", YarnrcFile: "/r/.yarnrc.yml"}
	got := map[string]finding.Severity{}
	for _, f := range CFG123.Check(tg) {
		got[f.File] = f.Severity
	}
	want := map[string]finding.Severity{"/r/git.exe": finding.Error, "/r/node.cmd": finding.Error, "/r/.venv/pyvenv.cfg": finding.Warn, "/r/.yarnrc.yml": finding.Warn}
	if len(got) != len(want) {
		t.Errorf("got %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %s, want %s", k, got[k], v)
		}
	}
	for _, y := range []string{".yarn/releases/yarn-4.5.1.cjs", "./.yarn/releases/yarn-1.22.0.js", ".yarn/releases/yarn-berry.cjs", "sub/.yarn/releases/yarn-4.0.0-rc.1.cjs"} {
		if f := CFG123.Check(&Target{ProjectDir: "/r", YarnPath: y}); len(f) != 0 {
			t.Errorf("%s: %+v", y, f)
		}
	}
	if f := CFG123.Check(&Target{ProjectDir: "/r", YarnPath: ".yarn/releases/boot.cjs"}); len(f) != 1 || !strings.Contains(f[0].Message, "yarnPath") {
		t.Errorf("non-release name: %+v", f)
	}
	if !ToolBinaryName("Git.EXE") || ToolBinaryName("gitx.exe") {
		t.Error("ToolBinaryName")
	}
	if CFG123.Check(&Target{RootFiles: []string{"git.exe"}}) != nil {
		t.Error("no project dir")
	}
}
