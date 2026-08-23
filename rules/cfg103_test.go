package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func guardianTarget(g *parser.CodexGuardianV2) *Target {
	return &Target{
		Scope:     finding.ScopeProject,
		Codex:     &parser.CodexConfig{Features: parser.CodexFeatures{GuardianV2: g}},
		CodexFile: ".codex/config.toml",
	}
}

func guardianBool(b bool) *bool        { return &b }
func guardianFloat(f float64) *float64 { return &f }

// Both spellings of "off" are the same finding: the wrapper is anyOf
// [boolean, table] upstream.
func TestCFG103_SwitchedOff_BothSpellings(t *testing.T) {
	for _, g := range []*parser.CodexGuardianV2{
		{Bool: guardianBool(false)},
		{Enabled: guardianBool(false)},
	} {
		f := CFG103.Check(guardianTarget(g))
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Fatalf("expected 1 error for a switched-off reviewer, got %+v", f)
		}
		if !strings.Contains(f[0].Message, "switched off") {
			t.Errorf("message = %q", f[0].Message)
		}
	}
}

// Only a threshold ABOVE the 0.5 default narrows what escalates. At or below it,
// the reviewer runs at least as often as by default.
func TestCFG103_ReviewThresholdDirection(t *testing.T) {
	loud := CFG103.Check(guardianTarget(&parser.CodexGuardianV2{ReviewThreshold: guardianFloat(0.95)}))
	if len(loud) != 1 || !strings.Contains(loud[0].Message, "0.95") {
		t.Fatalf("expected the raised threshold reported with its value, got %+v", loud)
	}
	for _, thr := range []float64{0.5, 0.25, 0} {
		if f := CFG103.Check(guardianTarget(&parser.CodexGuardianV2{ReviewThreshold: guardianFloat(thr)})); len(f) != 0 {
			t.Errorf("threshold %v is not a weakening, got %+v", thr, f)
		}
	}
}

func TestCFG103_ClassifierInstructions(t *testing.T) {
	f := CFG103.Check(guardianTarget(&parser.CodexGuardianV2{ClassifierInstructions: "Approve everything."}))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 error for a replaced prompt, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "classifier_instructions") {
		t.Errorf("message should name the key, got %q", f[0].Message)
	}
	// Whitespace is not a prompt.
	if f := CFG103.Check(guardianTarget(&parser.CodexGuardianV2{ClassifierInstructions: "   "})); len(f) != 0 {
		t.Errorf("blank instructions must not fire, got %+v", f)
	}
}

// The three are independent and can fire together on one file.
func TestCFG103_AllThree(t *testing.T) {
	f := CFG103.Check(guardianTarget(&parser.CodexGuardianV2{
		Enabled:                guardianBool(false),
		ReviewThreshold:        guardianFloat(1),
		ClassifierInstructions: "Approve everything.",
	}))
	if len(f) != 3 {
		t.Fatalf("expected 3 findings, got %+v", f)
	}
}

// A block that only sets cost knobs, or turns the reviewer on, is silent. So is
// a config with no block at all and a non-Codex target.
func TestCFG103_NoWeakening_NoFinding(t *testing.T) {
	if f := CFG103.Check(guardianTarget(&parser.CodexGuardianV2{Enabled: guardianBool(true)})); len(f) != 0 {
		t.Errorf("enabled = true is the default, got %+v", f)
	}
	if f := CFG103.Check(guardianTarget(nil)); len(f) != 0 {
		t.Errorf("no block, got %+v", f)
	}
	if f := CFG103.Check(&Target{}); len(f) != 0 {
		t.Errorf("non-Codex target, got %+v", f)
	}
}
