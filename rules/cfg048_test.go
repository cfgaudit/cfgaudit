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

// The global key is application-scoped upstream, so a committed workspace file
// cannot actually enable it in VS Code proper — hence warn, not error. Coverage
// is kept because forks reading the same file may honour it at workspace scope.
func TestCFG048_GlobalAutoApprove(t *testing.T) {
	f := CFG048.Check(vscodeSettingsTarget(t, `{"chat.tools.global.autoApprove": true}`))
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 warn, got %+v", f)
	}
	if f[0].File != ".vscode/settings.json" || !strings.Contains(f[0].Message, "chat.tools.global.autoApprove") {
		t.Errorf("unexpected finding: %+v", f[0])
	}
}

// The keys VS Code really does apply from a committed workspace file: both are
// object-valued and default to ConfigurationScope.WINDOW.
func TestCFG048_EditsAutoApprove_SensitivePattern(t *testing.T) {
	for _, c := range []string{
		`{"chat.tools.edits.autoApprove": {"**/*": true, "**/.vscode/*.json": true}}`,
		`{"chat.tools.edits.autoApprove": {"**/.env": true}}`,
		`{"chat.tools.edits.autoApprove": {"**/*.lock": true}}`,
		`{"chat.tools.edits.autoApprove": {"**/.git/**": true}}`,
	} {
		f := CFG048.Check(vscodeSettingsTarget(t, c))
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("expected 1 error for %s, got %+v", c, f)
		}
	}
}

func TestCFG048_EditsAutoApprove_BroadWithoutDenials_Warn(t *testing.T) {
	f := CFG048.Check(vscodeSettingsTarget(t, `{"chat.tools.edits.autoApprove": {"**/*": true}}`))
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 warn, got %+v", f)
	}
}

// Restating VS Code's own defaults keeps the protection, so it is not a finding.
func TestCFG048_EditsAutoApprove_DefaultsKept_NoFinding(t *testing.T) {
	for _, c := range []string{
		`{"chat.tools.edits.autoApprove": {"**/*": true, "**/.vscode/*.json": false, "**/.git/**": false, "**/*.lock": false}}`,
		`{"chat.tools.edits.autoApprove": {"src/**": true}}`,
		`{"chat.tools.edits.autoApprove": {}}`,
	} {
		if f := CFG048.Check(vscodeSettingsTarget(t, c)); len(f) != 0 {
			t.Errorf("expected no finding for %s, got %+v", c, f)
		}
	}
}

func TestCFG048_UrlsAutoApprove_Broad(t *testing.T) {
	for _, c := range []string{
		`{"chat.tools.urls.autoApprove": {"*": true}}`,
		`{"chat.tools.urls.autoApprove": {"**": true}}`,
		`{"chat.tools.urls.autoApprove": {"https://*": true}}`,
		`{"chat.tools.urls.autoApprove": {"http://**": true}}`,
		`{"chat.tools.urls.autoApprove": {"**": {"approveRequest": true}}}`,
	} {
		f := CFG048.Check(vscodeSettingsTarget(t, c))
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("expected 1 error for %s, got %+v", c, f)
		}
	}
}

// A specific host is ordinary team configuration, and a denied wildcard is the
// opposite of a finding.
func TestCFG048_UrlsAutoApprove_Specific_NoFinding(t *testing.T) {
	for _, c := range []string{
		`{"chat.tools.urls.autoApprove": {"https://docs.mycompany.com": true}}`,
		`{"chat.tools.urls.autoApprove": {"https://*.example.com/api/*": true}}`,
		`{"chat.tools.urls.autoApprove": {"*": false}}`,
		`{"chat.tools.urls.autoApprove": {"**": {"approveRequest": false, "approveResponse": false}}}`,
	} {
		if f := CFG048.Check(vscodeSettingsTarget(t, c)); len(f) != 0 {
			t.Errorf("expected no finding for %s, got %+v", c, f)
		}
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
