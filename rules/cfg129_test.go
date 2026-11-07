// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG129_Bytecode1398(t *testing.T) {
	f := CFG129.Check(&Target{ProjectDir: "/r", Bytecode: []BytecodeFile{
		{Path: "s/__pycache__/helper.cpython-312.pyc", Module: "helper", Kind: BytecodeReplacesSource},
		{Path: "s/__pycache__/gone.cpython-312.pyc", Module: "gone", Kind: BytecodeUncheckedNoSource},
		{Path: "s/lone.pyc", Module: "lone", Kind: BytecodeSourceless},
	}})
	if len(f) != 3 {
		t.Fatalf("%+v", f)
	}
	for i, want := range []struct {
		sev  finding.Severity
		text string
	}{{finding.Error, "without reading helper.py"}, {finding.Warn, "does not import it today"}, {finding.Warn, "imports it as module lone"}} {
		if f[i].Severity != want.sev || !strings.Contains(f[i].Message, want.text) {
			t.Errorf("finding %d: %+v", i, f[i])
		}
	}
	if CFG129.Check(&Target{Bytecode: []BytecodeFile{{Path: "a.pyc"}}}) != nil || CFG129.Check(nil) != nil {
		t.Error("no project dir")
	}
	if m := PycModule("helper.cpython-312.opt-1.pyc"); m != "helper" {
		t.Errorf("module %q", m)
	}
}
