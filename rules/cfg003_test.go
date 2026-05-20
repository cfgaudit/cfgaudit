package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG003_EnableAllProjectMcpServers(t *testing.T) {
	f := CFG003.Check(settingsTarget(t, `{"enableAllProjectMcpServers":true}`))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("expected Error severity, got %s", f[0].Severity)
	}
}

func TestCFG003_False_NoFinding(t *testing.T) {
	f := CFG003.Check(settingsTarget(t, `{"enableAllProjectMcpServers":false}`))
	if len(f) != 0 {
		t.Errorf("expected no finding when set to false, got %d", len(f))
	}
}

func TestCFG003_Absent_NoFinding(t *testing.T) {
	f := CFG003.Check(settingsTarget(t, `{"permissions":{"allow":["Bash(make *)"]}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding when key absent, got %d", len(f))
	}
}

func TestCFG003_NoSettings_NoFinding(t *testing.T) {
	f := CFG003.Check(&Target{})
	if len(f) != 0 {
		t.Errorf("expected no finding when settings absent, got %d", len(f))
	}
}

func TestCFG003_ExplicitAllowlist_NoFinding(t *testing.T) {
	f := CFG003.Check(settingsTarget(t, `{"enabledMcpjsonServers":["github","memory"]}`))
	if len(f) != 0 {
		t.Errorf("expected no finding when using explicit allowlist, got %d", len(f))
	}
}
