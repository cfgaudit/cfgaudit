package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func targetWithScope(t *testing.T, raw string, scope finding.Scope) *Target {
	t.Helper()
	s, err := parser.ParseSettingsBytes([]byte(raw), "test/settings.json")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return &Target{SettingsFile: "test/settings.json", Settings: s, Scope: scope}
}

// Project-scope CFG003: message must NOT contain the user-scope note.
func TestScope_CFG003_ProjectScope_NoNote(t *testing.T) {
	f := CFG003.Check(targetWithScope(t, `{"enableAllProjectMcpServers":true}`, finding.ScopeProject))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if strings.Contains(f[0].Message, "user-global scope") {
		t.Errorf("project-scope finding should not carry the user-scope note: %s", f[0].Message)
	}
}

// User-scope CFG003: message must contain the user-scope note; severity unchanged.
func TestScope_CFG003_UserScope_AddsNote(t *testing.T) {
	f := CFG003.Check(targetWithScope(t, `{"enableAllProjectMcpServers":true}`, finding.ScopeUser))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("CFG003 severity must remain Error at user scope, got %s", f[0].Severity)
	}
	if !strings.Contains(f[0].Message, "user-global scope") {
		t.Errorf("expected user-scope note in message, got: %s", f[0].Message)
	}
}

// CFG009 escalation: warn at project scope, error at user scope.
func TestScope_CFG009_ProjectScope_Warn(t *testing.T) {
	json := `{"hooks":{"PostToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"echo $X"}]}]}}`
	f := CFG009.Check(targetWithScope(t, json, finding.ScopeProject))
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 Warn finding at project scope, got %+v", f)
	}
}

func TestScope_CFG009_UserScope_Error(t *testing.T) {
	json := `{"hooks":{"PostToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"echo $X"}]}]}}`
	f := CFG009.Check(targetWithScope(t, json, finding.ScopeUser))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("CFG009 must escalate to Error at user scope, got %s", f[0].Severity)
	}
	if !strings.Contains(f[0].Message, "user-global scope") {
		t.Errorf("expected user-scope note in CFG009 message, got: %s", f[0].Message)
	}
}

// Run() back-fills Finding.Scope from Target.Scope so JSON consumers can filter.
func TestRun_BackfillsScope(t *testing.T) {
	stub := &stubRule{id: "TSTSCP", results: []finding.Finding{{RuleID: "TSTSCP", Severity: finding.Warn}}}
	withRules(t, stub)

	got := Run(&Target{SettingsFile: "x", Scope: finding.ScopeUser}, nil)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].Scope != finding.ScopeUser {
		t.Errorf("expected Scope to be back-filled to user, got %q", got[0].Scope)
	}
}

func TestRun_PreservesExplicitScope(t *testing.T) {
	stub := &stubRule{id: "TSTSCP2", results: []finding.Finding{{
		RuleID:   "TSTSCP2",
		Severity: finding.Warn,
		Scope:    finding.ScopeProjectLocal,
	}}}
	withRules(t, stub)

	got := Run(&Target{SettingsFile: "x", Scope: finding.ScopeUser}, nil)
	if got[0].Scope != finding.ScopeProjectLocal {
		t.Errorf("Run must not overwrite an explicit Scope; got %q", got[0].Scope)
	}
}
