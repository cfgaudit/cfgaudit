package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG079_BroadAllow(t *testing.T) {
	for _, allow := range []string{`"*"`, `"**"`, `"Bash"`, `"Bash(*)"`, `"PowerShell(*)"`} {
		json := `{"autoMode":{"allow":[` + allow + `]}}`
		f := CFG079.Check(settingsTarget(t, json))
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("expected 1 Error for allow %s, got %+v", allow, f)
		}
	}
}

func TestCFG079_SoftDenyDropsDefaults(t *testing.T) {
	// soft_deny present without "$defaults" — built-in deny baseline replaced.
	for _, json := range []string{
		`{"autoMode":{"soft_deny":["Read(./secret)"]}}`,
		`{"autoMode":{"soft_deny":[]}}`, // explicit empty still replaces defaults
	} {
		f := CFG079.Check(settingsTarget(t, json))
		if len(f) != 1 || f[0].Severity != finding.Warn {
			t.Errorf("expected 1 Warn for %s, got %+v", json, f)
		}
	}
}

func TestCFG079_Safe_NoFinding(t *testing.T) {
	for _, json := range []string{
		// narrow allow, no soft_deny
		`{"autoMode":{"allow":["Bash(ls:*)","Read(./src)"]}}`,
		// allow includes $defaults and only narrow custom rules
		`{"autoMode":{"allow":["$defaults","Bash(npm test)"]}}`,
		// soft_deny keeps the built-in defaults
		`{"autoMode":{"soft_deny":["$defaults","Read(./secret)"]}}`,
		// no autoMode at all
		`{"permissions":{"defaultMode":"auto"}}`,
		// empty autoMode object
		`{"autoMode":{}}`,
	} {
		if f := CFG079.Check(settingsTarget(t, json)); len(f) != 0 {
			t.Errorf("expected no finding for %s, got %+v", json, f)
		}
	}
}

func TestCFG079_BroadAllowAndSoftDenyDrop_TwoFindings(t *testing.T) {
	json := `{"autoMode":{"allow":["*","$defaults"],"soft_deny":["Read(./x)"]}}`
	f := CFG079.Check(settingsTarget(t, json))
	if len(f) != 2 {
		t.Fatalf("expected 2 findings (broad allow + soft_deny drop), got %d: %+v", len(f), f)
	}
}

func TestCFG079_MultipleBroadAllow_OneFinding(t *testing.T) {
	json := `{"autoMode":{"allow":["*","Bash(*)"]}}`
	f := CFG079.Check(settingsTarget(t, json))
	if len(f) != 1 {
		t.Fatalf("expected exactly 1 allow finding, got %d: %+v", len(f), f)
	}
}

func TestCFG079_NoSettings_NoFinding(t *testing.T) {
	if f := CFG079.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding without settings, got %+v", f)
	}
}
