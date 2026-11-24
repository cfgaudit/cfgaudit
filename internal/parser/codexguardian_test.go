// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCodexGuardianV2_BothSpellings(t *testing.T) {
	cases := []struct {
		body      string
		wantOff   bool
		wantThr   float64
		wantInstr string
	}{
		{"[features]\nguardianv2 = false\n", true, 0, ""},
		{"[features.guardianv2]\nenabled = false\nreview_threshold = 0.95\nclassifier_instructions = \"X\"\n", true, 0.95, "X"},
		{"[features.guardianv2]\nreview_threshold = 1\n", false, 1, ""},
	}
	for i, tc := range cases {
		p := filepath.Join(t.TempDir(), "config.toml")
		if err := os.WriteFile(p, []byte(tc.body), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := ParseCodexConfig(p)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		g := c.Features.GuardianV2
		if g == nil {
			t.Fatalf("case %d: block not decoded", i)
		}
		if g.Off() != tc.wantOff {
			t.Errorf("case %d: Off()=%v want %v", i, g.Off(), tc.wantOff)
		}
		if tc.wantThr != 0 && (g.ReviewThreshold == nil || *g.ReviewThreshold != tc.wantThr) {
			t.Errorf("case %d: threshold=%v want %v", i, g.ReviewThreshold, tc.wantThr)
		}
		if g.ClassifierInstructions != tc.wantInstr {
			t.Errorf("case %d: instructions=%q want %q", i, g.ClassifierInstructions, tc.wantInstr)
		}
	}
}

// #1879: the denial-reconsideration flag is a plain boolean under [features],
// decoded next to guardianv2 without disturbing it.
func TestCodexFeatures_GuardianDenialReconsideration(t *testing.T) {
	on, off := true, false
	for _, tc := range []struct {
		body string
		want *bool
	}{
		{"[features]\nguardian_denial_reconsideration = true\n", &on},
		{"[features]\nguardian_denial_reconsideration = false\n", &off},
		{"[features]\nguardianv2 = false\n", nil},
	} {
		c := parseCodexTOML(t, tc.body)
		got := c.Features.GuardianDenialReconsideration
		if (got == nil) != (tc.want == nil) || (got != nil && *got != *tc.want) {
			t.Errorf("%q: got %v, want %v", tc.body, got, tc.want)
		}
	}
	c := parseCodexTOML(t, "[features]\nguardian_denial_reconsideration = true\n\n[features.guardianv2]\nenabled = false\n")
	if c.Features.GuardianDenialReconsideration == nil || !*c.Features.GuardianDenialReconsideration || !c.Features.GuardianV2.Off() {
		t.Errorf("both keys should decode, got %+v", c.Features)
	}
}
