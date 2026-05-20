package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func settingsTarget(t *testing.T, json string) *Target {
	t.Helper()
	s, err := parser.ParseSettingsBytes([]byte(json), "test/settings.json")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return &Target{SettingsFile: "test/settings.json", Settings: s}
}

func TestCFG001_UnrestrictedBash(t *testing.T) {
	f := CFG001.Check(settingsTarget(t, `{"permissions":{"allow":["Bash(*)"]}}`))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("expected Error severity, got %s", f[0].Severity)
	}
}

func TestCFG001_UnrestrictedBashDoubleWildcard(t *testing.T) {
	f := CFG001.Check(settingsTarget(t, `{"permissions":{"allow":["Bash(**)"]}}`))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for Bash(**), got %d", len(f))
	}
}

func TestCFG001_ScopedBash_NoFinding(t *testing.T) {
	f := CFG001.Check(settingsTarget(t, `{"permissions":{"allow":["Bash(go test ./...)","Bash(make *)","Edit(src/*)"]
}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding for scoped Bash, got %d", len(f))
	}
}

func TestCFG001_NoPermissions_NoFinding(t *testing.T) {
	f := CFG001.Check(settingsTarget(t, `{"env":{"FOO":"bar"}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding when permissions absent, got %d", len(f))
	}
}

func TestCFG001_EmptyAllow_NoFinding(t *testing.T) {
	f := CFG001.Check(settingsTarget(t, `{"permissions":{"allow":[]}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding for empty allow list, got %d", len(f))
	}
}

func TestCFG001_NoSettings_NoFinding(t *testing.T) {
	f := CFG001.Check(&Target{})
	if len(f) != 0 {
		t.Errorf("expected no finding when settings absent, got %d", len(f))
	}
}

func TestCFG001_UnrestrictedEditWrite_NoFinding(t *testing.T) {
	// CFG001 must not flag Edit(*) or Write(*) — those belong to CFG002.
	f := CFG001.Check(settingsTarget(t, `{"permissions":{"allow":["Edit(*)","Write(*)"]}}`))
	if len(f) != 0 {
		t.Errorf("expected no CFG001 finding for Edit(*)/Write(*), got %d", len(f))
	}
}
