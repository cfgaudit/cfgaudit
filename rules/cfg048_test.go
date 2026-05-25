package rules

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func vscodeSettingsTarget(t *testing.T, raw string) *Target {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("bad test JSON: %v", err)
	}
	return &Target{
		Scope:              finding.ScopeProject,
		VSCodeSettingsFile: ".vscode/settings.json",
		VSCodeSettings:     &parser.VSCodeSettings{Raw: m},
	}
}

func TestCFG048_GlobalAutoApprove(t *testing.T) {
	f := CFG048.Check(vscodeSettingsTarget(t, `{"chat.tools.global.autoApprove": true}`))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 error, got %+v", f)
	}
	if f[0].File != ".vscode/settings.json" || !strings.Contains(f[0].Message, "chat.tools.global.autoApprove") {
		t.Errorf("unexpected finding: %+v", f[0])
	}
}

func TestCFG048_LegacyKey(t *testing.T) {
	f := CFG048.Check(vscodeSettingsTarget(t, `{"chat.tools.autoApprove": true}`))
	if len(f) != 1 {
		t.Fatalf("expected legacy key flagged, got %+v", f)
	}
}

func TestCFG048_NotFlagged(t *testing.T) {
	cases := []string{
		`{"chat.tools.global.autoApprove": false}`,           // explicit false
		`{"editor.tabSize": 2}`,                              // unrelated
		`{"chat.tools.terminal.autoApprove": {"npm": true}}`, // granular object form, not blanket
		`{"chat.tools.autoApprove": "true"}`,                 // string, not boolean
	}
	for _, c := range cases {
		if f := CFG048.Check(vscodeSettingsTarget(t, c)); len(f) != 0 {
			t.Errorf("expected no finding for %s, got %+v", c, f)
		}
	}
}

func TestCFG048_NoSettings_NoFinding(t *testing.T) {
	if f := CFG048.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding when no settings.json, got %+v", f)
	}
}
