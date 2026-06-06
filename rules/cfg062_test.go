package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func boolPtr(b bool) *bool { return &b }

func TestCFG062_ExplicitFalseNoAllowlist_Warn(t *testing.T) {
	gs := &parser.GeminiSettings{Security: &parser.GeminiSecurity{BlockGitExtensions: boolPtr(false)}}
	f := CFG062.Check(geminiTarget(gs))
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 Warn, got %+v", f)
	}
}

func TestCFG062_NoFinding(t *testing.T) {
	cases := []*parser.GeminiSettings{
		{Security: &parser.GeminiSecurity{BlockGitExtensions: boolPtr(true)}},                                       // explicitly blocked
		{Security: &parser.GeminiSecurity{}},                                                                        // absent (nil) — not flagged
		{Security: &parser.GeminiSecurity{BlockGitExtensions: boolPtr(false), AllowedExtensions: []string{"x/.*"}}}, // allow-list constrains it
		{}, // no security section
	}
	for i, gs := range cases {
		if f := CFG062.Check(geminiTarget(gs)); len(f) != 0 {
			t.Errorf("case %d: expected no finding, got %+v", i, f)
		}
	}
	if f := CFG062.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding for non-Gemini target, got %+v", f)
	}
}
