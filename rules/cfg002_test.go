package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG002_UnrestrictedEdit(t *testing.T) {
	f := CFG002.Check(settingsTarget(t, `{"permissions":{"allow":["Edit(*)"]}}`))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity, got %s", f[0].Severity)
	}
}

func TestCFG002_UnrestrictedWrite(t *testing.T) {
	f := CFG002.Check(settingsTarget(t, `{"permissions":{"allow":["Write(*)"]}}`))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for Write(*), got %d", len(f))
	}
}

func TestCFG002_BothUnrestricted(t *testing.T) {
	f := CFG002.Check(settingsTarget(t, `{"permissions":{"allow":["Edit(*)","Write(*)"]}}`))
	if len(f) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(f))
	}
}

func TestCFG002_ScopedEdit_NoFinding(t *testing.T) {
	f := CFG002.Check(settingsTarget(t, `{"permissions":{"allow":["Edit(src/*)","Write(output/*)","Edit(**.go)"]}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding for scoped Edit/Write, got %d", len(f))
	}
}

func TestCFG002_NoPermissions_NoFinding(t *testing.T) {
	f := CFG002.Check(settingsTarget(t, `{}`))
	if len(f) != 0 {
		t.Errorf("expected no finding when permissions absent, got %d", len(f))
	}
}

func TestCFG002_UnrestrictedBash_NoFinding(t *testing.T) {
	// CFG002 must not flag Bash(*) — that belongs to CFG001.
	f := CFG002.Check(settingsTarget(t, `{"permissions":{"allow":["Bash(*)"]}}`))
	if len(f) != 0 {
		t.Errorf("expected no CFG002 finding for Bash(*), got %d", len(f))
	}
}
