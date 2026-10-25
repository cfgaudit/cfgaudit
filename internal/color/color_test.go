// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package color

import (
	"bytes"
	"strings"
	"testing"
)

func TestEnabled(t *testing.T) {
	var buf bytes.Buffer // not a terminal
	for _, tc := range []struct {
		noColor           bool
		noEnv, force, cli string
		want              bool
	}{
		{false, "", "", "", false},
		{false, "", "1", "", true},
		{false, "", "", "1", true},
		{false, "", "0", "", false},
		{false, "1", "1", "", false},
		{true, "", "1", "", false},
	} {
		t.Setenv("NO_COLOR", tc.noEnv)
		t.Setenv("FORCE_COLOR", tc.force)
		t.Setenv("CLICOLOR_FORCE", tc.cli)
		if got := Enabled(tc.noColor, &buf); got != tc.want {
			t.Errorf("%+v: got %v", tc, got)
		}
	}
}

func TestTextLine(t *testing.T) {
	got := TextLine("CLAUDE.md:5:1 [error] CFG029: CLAUDE.md line 5 says [warn] CFG001: x")
	want := "CLAUDE.md:5:1 [" + red + "error" + reset + "] " + bold + "CFG029" + reset + ": CLAUDE.md line 5 says [warn] CFG001: x"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
	for _, l := range []string{"", "cfgaudit 1.18.1 — 3 findings"} {
		if TextLine(l) != l {
			t.Errorf("%q changed", l)
		}
	}
}

// The table is coloured after alignment, so stripping the escape codes gives
// back the aligned table byte for byte.
func TestTable(t *testing.T) {
	in := "SEVERITY  RULE    LOCATION\nerror     CFG001  a.json\nwarn      CFG006  a.json\ninfo      CFG004  b.json\n\ncfgaudit 1.18.1 — 3 findings\n"
	out := Table(in)
	if !strings.Contains(out, yellow+"warn"+reset+"      "+bold+"CFG006"+reset) {
		t.Errorf("row not coloured: %q", out)
	}
	plain := strings.NewReplacer(reset, "", bold, "", red, "", yellow, "", cyan, "").Replace(out)
	if plain != in {
		t.Errorf("alignment changed:\n%q\n%q", plain, in)
	}
}
