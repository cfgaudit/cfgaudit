package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG040_Unrestricted(t *testing.T) {
	for _, entry := range []string{"WebFetch", "WebFetch()", "WebFetch(*)", "WebFetch(domain:*)", "WebFetch(url:*)"} {
		json := `{"permissions":{"allow":["` + entry + `"]}}`
		f := CFG040.Check(settingsTarget(t, json))
		if len(f) != 1 || f[0].Severity != finding.Warn {
			t.Errorf("expected 1 Warn for %q, got %+v", entry, f)
		}
	}
}

func TestCFG040_ScopedDomain_NoFinding(t *testing.T) {
	for _, entry := range []string{"WebFetch(domain:api.example.com)", "WebFetch(domain:*.example.com)", "WebFetch(url:https://x.com/y)"} {
		json := `{"permissions":{"allow":["` + entry + `"]}}`
		if f := CFG040.Check(settingsTarget(t, json)); len(f) != 0 {
			t.Errorf("expected no finding for scoped %q, got %+v", entry, f)
		}
	}
}

func TestCFG040_OtherEntries_NoFinding(t *testing.T) {
	f := CFG040.Check(settingsTarget(t, `{"permissions":{"allow":["Bash(make *)","Read(README.md)"]}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding for non-WebFetch entries, got %+v", f)
	}
}

func TestCFG040_NoPermissions_NoFinding(t *testing.T) {
	if f := CFG040.Check(settingsTarget(t, `{"env":{"X":"y"}}`)); len(f) != 0 {
		t.Errorf("expected no finding without permissions, got %+v", f)
	}
}
