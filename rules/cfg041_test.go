package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG041_DenyMissingEnv(t *testing.T) {
	f := CFG041.Check(settingsTarget(t, `{"permissions":{"deny":["Bash(rm -rf *)"]}}`))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "Read(**/.env)") {
		t.Errorf("expected suggested patterns in message, got: %s", f[0].Message)
	}
}

func TestCFG041_EnvCovered_NoFinding(t *testing.T) {
	for _, deny := range []string{
		`"Read(.env)"`,
		`"Read(.env.*)"`,
		`"Read(.env*)"`,
		`"Read(*.env)"`,
		`"Read(**/.env)"`,
		`"Read(**/.env.*)"`,
	} {
		json := `{"permissions":{"deny":["Bash(rm -rf *)",` + deny + `]}}`
		if f := CFG041.Check(settingsTarget(t, json)); len(f) != 0 {
			t.Errorf("expected no finding when deny has %s, got %+v", deny, f)
		}
	}
}

func TestCFG041_NoDenyBlock_NoFinding(t *testing.T) {
	// absent / empty deny is CFG006's responsibility
	if f := CFG041.Check(settingsTarget(t, `{"permissions":{"allow":["Bash(make *)"]}}`)); len(f) != 0 {
		t.Errorf("expected no finding when deny absent, got %+v", f)
	}
	if f := CFG041.Check(settingsTarget(t, `{"permissions":{"deny":[]}}`)); len(f) != 0 {
		t.Errorf("expected no finding when deny empty, got %+v", f)
	}
}

func TestCFG041_NoEnvironmentFalsePositive(t *testing.T) {
	// ".environment" should not count as .env coverage
	f := CFG041.Check(settingsTarget(t, `{"permissions":{"deny":["Read(.environment)"]}}`))
	if len(f) != 1 {
		t.Errorf("expected finding (.environment is not .env coverage), got %+v", f)
	}
}

func TestCFG041_NoPermissions_NoFinding(t *testing.T) {
	if f := CFG041.Check(settingsTarget(t, `{"env":{"X":"y"}}`)); len(f) != 0 {
		t.Errorf("expected no finding without permissions, got %+v", f)
	}
}
