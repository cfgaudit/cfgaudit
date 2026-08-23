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

// #434: chat.permissions.default picks the mode every new chat session starts
// in. It is the successor to the CVE-2025-53773 setting and, unlike
// chat.tools.global.autoApprove, is genuinely workspace-honoured (WINDOW scope,
// not restricted).
func TestCFG048_PermissionLevelWeakening(t *testing.T) {
	for _, v := range []string{"autoApprove", "autopilot", "AUTOPILOT"} {
		t.Run(v, func(t *testing.T) {
			f := CFG048.Check(vscodeSettingsTarget(t, `{"chat.permissions.default": "`+v+`"}`))
			if len(f) != 1 || f[0].Severity != finding.Error {
				t.Fatalf("expected 1 Error for %q, got %+v", v, f)
			}
			if !strings.Contains(f[0].Message, "chat.permissions.default") {
				t.Errorf("message should name the key, got %q", f[0].Message)
			}
		})
	}
}

// "assisted" exists on the ChatPermissionLevel enum but is not among the values
// this setting registers, so flagging it would report something VS Code's own
// schema rejects.
func TestCFG048_PermissionLevelNonWeakeningValues(t *testing.T) {
	for _, v := range []string{"default", "assisted", "", "nonsense"} {
		t.Run("value="+v, func(t *testing.T) {
			if f := CFG048.Check(vscodeSettingsTarget(t, `{"chat.permissions.default": "`+v+`"}`)); len(f) != 0 {
				t.Errorf("expected no findings for %q, got %+v", v, f)
			}
		})
	}
}

// #468: chat.defaultConfiguration carries the chat.permissions.default decisions
// in an object. Both keys are registered upstream, so both have to be read.
func TestCFG048_DefaultConfigurationWeakening(t *testing.T) {
	for _, c := range []struct{ name, body, field string }{
		{"approvals", `{"approvals": "allowAll"}`, "approvals"},
		{"approvals mixed case", `{"approvals": "ALLOWALL"}`, "approvals"},
		{"mode", `{"mode": "autopilot"}`, "mode"},
		{"mode padded", `{"mode": " autopilot "}`, "mode"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := CFG048.Check(vscodeSettingsTarget(t, `{"chat.defaultConfiguration": `+c.body+`}`))
			if len(f) != 1 || f[0].Severity != finding.Error {
				t.Fatalf("expected 1 Error, got %+v", f)
			}
			if !strings.Contains(f[0].Message, "chat.defaultConfiguration") || !strings.Contains(f[0].Message, c.field) {
				t.Errorf("message should name the key and the field, got %q", f[0].Message)
			}
		})
	}
}

// Both fields set is two decisions waived, each separately removable, so each is
// reported on its own.
func TestCFG048_DefaultConfigurationBothFields(t *testing.T) {
	f := CFG048.Check(vscodeSettingsTarget(t, `{"chat.defaultConfiguration": {"mode": "autopilot", "approvals": "allowAll"}}`))
	if len(f) != 2 {
		t.Fatalf("expected 2 findings, got %+v", f)
	}
}

// The flat key and the object are both registered, so a file carrying both is
// two findings rather than a deduplicated one.
func TestCFG048_DefaultConfigurationAlongsideFlatKey(t *testing.T) {
	f := CFG048.Check(vscodeSettingsTarget(t, `{
      "chat.permissions.default": "autopilot",
      "chat.defaultConfiguration": {"approvals": "allowAll"}
    }`))
	if sev := severities(f); sev[finding.Error] != 2 {
		t.Fatalf("expected 2 Errors, got %+v", f)
	}
}

// The values that do not waive a confirmation, plus the shapes that are not a
// value at all. "assisted" and "plan" are real enum members that keep a decision
// point, so reporting them would be noise.
func TestCFG048_DefaultConfigurationNonWeakening(t *testing.T) {
	for _, c := range []string{
		`{"chat.defaultConfiguration": {"approvals": "default"}}`,
		`{"chat.defaultConfiguration": {"approvals": "assisted"}}`,
		`{"chat.defaultConfiguration": {"mode": "interactive"}}`,
		`{"chat.defaultConfiguration": {"mode": "plan"}}`,
		`{"chat.defaultConfiguration": {}}`,
		`{"chat.defaultConfiguration": {"mode": true}}`,        // wrong type
		`{"chat.defaultConfiguration": "autopilot"}`,           // not an object
		`{"chat.defaultConfiguration": {"other": "allowAll"}}`, // unrelated field
	} {
		if f := CFG048.Check(vscodeSettingsTarget(t, c)); len(f) != 0 {
			t.Errorf("expected no finding for %s, got %+v", c, f)
		}
	}
}

func TestCFG048_TerminalCatchAllPattern(t *testing.T) {
	for _, pat := range []string{`/.*/`, `/.*/i`, `/^.*$/`, `/.+/`, `/(.*)/ `, ``} {
		t.Run("pattern="+pat, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{pat: true})
			if err != nil {
				t.Fatal(err)
			}
			f := CFG048.Check(vscodeSettingsTarget(t, `{"chat.tools.terminal.autoApprove": `+string(body)+`}`))
			if len(f) != 1 || f[0].Severity != finding.Error {
				t.Fatalf("expected 1 Error for %q, got %+v", pat, f)
			}
		})
	}
}

// Naming the commands a project runs is what the setting is for; flagging that
// would make the rule noise.
func TestCFG048_TerminalSpecificPatternsSilent(t *testing.T) {
	f := CFG048.Check(vscodeSettingsTarget(t, `{"chat.tools.terminal.autoApprove": {
      "npm run test": true,
      "/^git (status|diff)/": true,
      "cargo build": {"approve": true, "matchCommandLine": true},
      "rm": false
    }}`))
	if len(f) != 0 {
		t.Errorf("specific patterns must not be flagged, got %+v", f)
	}
}

// A catch-all set to false, or to an object that denies, is a denial and must
// not be reported as an approval.
func TestCFG048_TerminalCatchAllDenialSilent(t *testing.T) {
	for _, val := range []string{`false`, `{"approve": false}`, `{"matchCommandLine": true}`} {
		t.Run(val, func(t *testing.T) {
			f := CFG048.Check(vscodeSettingsTarget(t, `{"chat.tools.terminal.autoApprove": {"/.*/": `+val+`}}`))
			if len(f) != 0 {
				t.Errorf("expected no findings for a catch-all set to %s, got %+v", val, f)
			}
		})
	}
}

// The object form approves through its `approve` field; matchCommandLine only
// changes what the pattern matches against.
func TestCFG048_TerminalCatchAllObjectApproves(t *testing.T) {
	f := CFG048.Check(vscodeSettingsTarget(t,
		`{"chat.tools.terminal.autoApprove": {"/.*/": {"approve": true, "matchCommandLine": true}}}`))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error, got %+v", f)
	}
}

func TestCFG048_TerminalIgnoreDefaultRules(t *testing.T) {
	f := CFG048.Check(vscodeSettingsTarget(t, `{"chat.tools.terminal.ignoreDefaultAutoApproveRules": true}`))
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 Warn, got %+v", f)
	}
	if f := CFG048.Check(vscodeSettingsTarget(t, `{"chat.tools.terminal.ignoreDefaultAutoApproveRules": false}`)); len(f) != 0 {
		t.Errorf("false is the default and must not be flagged, got %+v", f)
	}
}

// All three #434 keys in one file, each reported once and on its own merits.
func TestCFG048_AllNewKeysTogether(t *testing.T) {
	f := CFG048.Check(vscodeSettingsTarget(t, `{
      "chat.permissions.default": "autopilot",
      "chat.tools.terminal.autoApprove": {"/.*/": true, "npm test": true},
      "chat.tools.terminal.ignoreDefaultAutoApproveRules": true
    }`))
	sev := severities(f)
	if sev[finding.Error] != 2 || sev[finding.Warn] != 1 {
		t.Fatalf("expected 2 Error + 1 Warn, got %+v", f)
	}
}

// #526: chat.useClaudeHooks defaults to false and only true loosens. The default
// hook locations already include the repository's own .claude/settings.json, so
// a committed true switches on execution of hooks the repository ships.
func TestCFG048_UseClaudeHooks(t *testing.T) {
	f := CFG048.Check(vscodeSettingsTarget(t, `{"chat.useClaudeHooks": true}`))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 error, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "chat.useClaudeHooks") || !strings.Contains(f[0].Message, "restricted") {
		t.Errorf("message should name the key and the trust gate, got %q", f[0].Message)
	}
	if got := CFG048.Check(vscodeSettingsTarget(t, `{"chat.useClaudeHooks": false}`)); len(got) != 0 {
		t.Errorf("false is the default, got %+v", got)
	}
}

// Only a path outside DEFAULT_HOOK_FILE_PATHS is a new location, and only when
// it is enabled: disabling a default path is the narrowing direction.
func TestCFG048_HookFilesLocations(t *testing.T) {
	f := CFG048.Check(vscodeSettingsTarget(t, `{"chat.hookFilesLocations": {
      ".claude/settings.json": true, "~/.copilot/hooks": false, "tools/agent-hooks": true}}`))
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 warn, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "tools/agent-hooks") {
		t.Errorf("message should name the registered path, got %q", f[0].Message)
	}
	for _, absent := range []string{".claude/settings.json", "~/.copilot/hooks"} {
		if strings.Contains(f[0].Message, absent) {
			t.Errorf("default path %q must not be reported: %q", absent, f[0].Message)
		}
	}
	if got := CFG048.Check(vscodeSettingsTarget(t, `{"chat.hookFilesLocations": {".github/hooks": true}}`)); len(got) != 0 {
		t.Errorf("enabling a default path registers nothing new, got %+v", got)
	}
}

// (b) The terminal keys are restricted, chat.permissions.default is not, and the
// messages must differ accordingly.
func TestCFG048_TrustNoteOnlyOnRestrictedKeys(t *testing.T) {
	term := CFG048.Check(vscodeSettingsTarget(t, `{"chat.tools.terminal.autoApprove": {"/.*/": true}}`))
	if len(term) != 1 || !strings.Contains(term[0].Message, "restricted") {
		t.Fatalf("terminal finding should carry the trust note, got %+v", term)
	}
	if strings.Contains(term[0].Message, "for anyone who opens this repo") {
		t.Errorf("the overstated wording must be gone: %q", term[0].Message)
	}
	perm := CFG048.Check(vscodeSettingsTarget(t, `{"chat.permissions.default": "autoApprove"}`))
	if len(perm) != 1 {
		t.Fatalf("expected the permission finding, got %+v", perm)
	}
	if strings.Contains(perm[0].Message, "restricted") {
		t.Errorf("chat.permissions.default is not restricted; its message must not claim a trust gate: %q", perm[0].Message)
	}
}
