// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG137_HiddenBehindSpaces(t *testing.T) {
	hidden := strings.Repeat(" ", 150) + "secret instruction"
	f := CFG137.Check(claudeMDTarget("visible text" + hidden))
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("want 1 warn, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "hides text behind 150 blank characters") {
		t.Errorf("message: %s", f[0].Message)
	}
	// 149 spaces is not enough.
	if f := CFG137.Check(claudeMDTarget("visible text" + strings.Repeat(" ", 149) + "secret")); len(f) != 0 {
		t.Errorf("149 spaces reported: %+v", f)
	}
}

func TestCFG137_SkipsTablesAndFences(t *testing.T) {
	// Markdown table row.
	line := "| a |" + strings.Repeat(" ", 150) + "hidden |"
	if f := CFG137.Check(claudeMDTarget(line)); len(f) != 0 {
		t.Errorf("table row reported: %+v", f)
	}
	// Fenced code block.
	content := "```\nvisible" + strings.Repeat(" ", 150) + "hidden\n```"
	if f := CFG137.Check(claudeMDTarget(content)); len(f) != 0 {
		t.Errorf("fenced code reported: %+v", f)
	}
	// Run followed only by a comment terminator.
	if f := CFG137.Check(claudeMDTarget("visible" + strings.Repeat(" ", 150) + "-->")); len(f) != 0 {
		t.Errorf("terminator run reported: %+v", f)
	}
}

func TestCFG137_UnicodeSpaces(t *testing.T) {
	// 150 U+00A0 count as 150 runes.
	content := "visible" + strings.Repeat("\u00a0", 150) + "hidden"
	f := CFG137.Check(claudeMDTarget(content))
	if len(f) != 1 {
		t.Fatalf("want 1, got %+v", f)
	}
}

func TestCFG137_Nil(t *testing.T) {
	if f := CFG137.Check(nil); f != nil {
		t.Error("nil target")
	}
}
