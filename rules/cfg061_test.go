package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func TestCFG061_BroadSandboxPath_Error(t *testing.T) {
	for _, p := range []string{"/", "~", "$HOME", "..", "/*", "../etc"} {
		gs := &parser.GeminiSettings{Tools: &parser.GeminiTools{SandboxAllowedPaths: []string{p}}}
		f := CFG061.Check(geminiTarget(gs))
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("expected 1 Error for broad path %q, got %+v", p, f)
		}
	}
}

func TestCFG061_NetworkAccess_Warn(t *testing.T) {
	gs := &parser.GeminiSettings{Tools: &parser.GeminiTools{SandboxNetworkAccess: true}}
	f := CFG061.Check(geminiTarget(gs))
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 Warn for sandboxNetworkAccess, got %+v", f)
	}
}

func TestCFG061_BothSignals(t *testing.T) {
	gs := &parser.GeminiSettings{Tools: &parser.GeminiTools{
		SandboxAllowedPaths:  []string{"/"},
		SandboxNetworkAccess: true,
	}}
	if f := CFG061.Check(geminiTarget(gs)); len(f) != 2 {
		t.Fatalf("expected 2 findings (path + network), got %+v", f)
	}
}

func TestCFG061_ScopedSandbox_NoFinding(t *testing.T) {
	gs := &parser.GeminiSettings{Tools: &parser.GeminiTools{
		SandboxAllowedPaths:  []string{"./build", "./.cache", "/tmp/work"},
		SandboxNetworkAccess: false,
	}}
	if f := CFG061.Check(geminiTarget(gs)); len(f) != 0 {
		t.Errorf("expected no finding for scoped sandbox, got %+v", f)
	}
	if f := CFG061.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding for non-Gemini target, got %+v", f)
	}
}
