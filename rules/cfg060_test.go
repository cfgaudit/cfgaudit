package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func geminiTarget(gs *parser.GeminiSettings) *Target {
	return &Target{Scope: finding.ScopeProject, Gemini: gs, GeminiFile: ".gemini/settings.json"}
}

func TestCFG060_AutoEdit_Error(t *testing.T) {
	for _, mode := range []string{"auto_edit", "AUTO_EDIT", "yolo"} {
		gs := &parser.GeminiSettings{General: &parser.GeminiGeneral{DefaultApprovalMode: mode}}
		f := CFG060.Check(geminiTarget(gs))
		if len(f) != 1 || f[0].Severity != finding.Error || f[0].File != ".gemini/settings.json" {
			t.Errorf("expected 1 Error for mode %q, got %+v", mode, f)
		}
	}
}

func TestCFG060_SafeModes_NoFinding(t *testing.T) {
	for _, mode := range []string{"default", "plan", ""} {
		gs := &parser.GeminiSettings{General: &parser.GeminiGeneral{DefaultApprovalMode: mode}}
		if f := CFG060.Check(geminiTarget(gs)); len(f) != 0 {
			t.Errorf("expected no finding for mode %q, got %+v", mode, f)
		}
	}
	// no general section, and non-Gemini target
	if f := CFG060.Check(geminiTarget(&parser.GeminiSettings{})); len(f) != 0 {
		t.Errorf("expected no finding without general, got %+v", f)
	}
	if f := CFG060.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding for non-Gemini target, got %+v", f)
	}
}
