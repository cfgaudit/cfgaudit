package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG044_DenyMissingSSH(t *testing.T) {
	f := CFG044.Check(settingsTarget(t, `{"permissions":{"deny":["Read(.env)","Read(**/*.pem)"]}}`))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "Read(**/.ssh/**)") {
		t.Errorf("expected suggested pattern in message, got: %s", f[0].Message)
	}
}

func TestCFG044_Covered_NoFinding(t *testing.T) {
	for _, deny := range []string{
		`"Read(**/.ssh/**)"`,
		`"Read(~/.ssh/*)"`,
		`"Read(.ssh/*)"`,
		`"Read(**/id_rsa)"`,
		`"Read(**/id_ed25519)"`,
		`"Read(**/id_ecdsa)"`,
		`"Read(**/id_dsa)"`,
	} {
		json := `{"permissions":{"deny":["Bash(rm -rf *)",` + deny + `]}}`
		if f := CFG044.Check(settingsTarget(t, json)); len(f) != 0 {
			t.Errorf("expected no finding when deny has %s, got %+v", deny, f)
		}
	}
}

func TestCFG044_NoDenyBlock_NoFinding(t *testing.T) {
	if f := CFG044.Check(settingsTarget(t, `{"permissions":{"allow":["Bash(make *)"]}}`)); len(f) != 0 {
		t.Errorf("expected no finding when deny absent, got %+v", f)
	}
}
