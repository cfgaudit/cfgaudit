package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func codexTarget(cc *parser.CodexConfig) *Target {
	return &Target{Scope: finding.ScopeUser, Codex: cc, CodexFile: "~/.codex/config.toml"}
}

func TestCFG063_Never_Error(t *testing.T) {
	f := CFG063.Check(codexTarget(&parser.CodexConfig{ApprovalPolicy: "never"}))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error for approval_policy=never, got %+v", f)
	}
}

func TestCFG063_OnFailure_Warn(t *testing.T) {
	f := CFG063.Check(codexTarget(&parser.CodexConfig{ApprovalPolicy: "on-failure"}))
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 Warn for approval_policy=on-failure, got %+v", f)
	}
}

func TestCFG063_SafeAndAbsent_NoFinding(t *testing.T) {
	for _, p := range []string{"untrusted", "on-request", ""} {
		if f := CFG063.Check(codexTarget(&parser.CodexConfig{ApprovalPolicy: p})); len(f) != 0 {
			t.Errorf("expected no finding for approval_policy=%q, got %+v", p, f)
		}
	}
	if f := CFG063.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding for non-Codex target, got %+v", f)
	}
}

func TestCFG064_DangerFullAccess_Error(t *testing.T) {
	f := CFG064.Check(codexTarget(&parser.CodexConfig{SandboxMode: "danger-full-access"}))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error for sandbox_mode=danger-full-access, got %+v", f)
	}
}

func TestCFG064_SafeAndAbsent_NoFinding(t *testing.T) {
	for _, m := range []string{"read-only", "workspace-write", ""} {
		if f := CFG064.Check(codexTarget(&parser.CodexConfig{SandboxMode: m})); len(f) != 0 {
			t.Errorf("expected no finding for sandbox_mode=%q, got %+v", m, f)
		}
	}
	if f := CFG064.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding for non-Codex target, got %+v", f)
	}
}
