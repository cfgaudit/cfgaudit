package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func qwenApprovalTarget(mode string) *Target {
	return &Target{
		Scope:    finding.ScopeProject,
		Qwen:     &parser.QwenSettings{Tools: &parser.QwenTools{ApprovalMode: mode}},
		QwenFile: ".qwen/settings.json",
	}
}

func TestCFG091_Yolo(t *testing.T) {
	for _, mode := range []string{"yolo", "YOLO", " Yolo "} {
		f := CFG091.Check(qwenApprovalTarget(mode))
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Fatalf("%q: expected 1 Error, got %+v", mode, f)
		}
		if f[0].File != ".qwen/settings.json" {
			t.Errorf("%q: file = %q", mode, f[0].File)
		}
		if !strings.Contains(f[0].Message, "yolo") {
			t.Errorf("%q: message = %q", mode, f[0].Message)
		}
	}
}

// auto is qwen's shipped default and classifier-gated; auto-edit is stricter than
// that default; default/plan prompt. None is a committed escalation footgun.
func TestCFG091_NonYoloModes_NoFinding(t *testing.T) {
	for _, mode := range []string{"auto", "auto-edit", "default", "plan", ""} {
		if f := CFG091.Check(qwenApprovalTarget(mode)); len(f) != 0 {
			t.Errorf("%q: expected no finding, got %+v", mode, f)
		}
	}
}

func TestCFG091_NoQwenOrTools_NoFinding(t *testing.T) {
	for _, tgt := range []*Target{
		{},
		{Qwen: &parser.QwenSettings{}},
		{Qwen: &parser.QwenSettings{Tools: &parser.QwenTools{}}},
	} {
		if f := CFG091.Check(tgt); len(f) != 0 {
			t.Errorf("expected no finding, got %+v", f)
		}
	}
}
