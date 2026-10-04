package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func permTarget(p *parser.Permissions, hooks map[string][]parser.HookGroup) *Target {
	return &Target{Scope: finding.ScopeProject, SettingsFile: ".claude/settings.json", Settings: &parser.Settings{Permissions: p, Hooks: hooks}}
}

// The characters measured to disable a rule on 2.1.288, in each list.
func TestCFG111_HiddenCharacters(t *testing.T) {
	for _, rule := range []string{"Bash(tou\u200bch:*)", "Bash(tou\x00ch:*)", "Bash(\u202etouch:*)", "Bash(tou\u00adch:*)", "Read(./.e\u2060nv)", "Bash(rm\U000E0041:*)", "Bash(rm\u3164:*)"} {
		f := CFG111.Check(permTarget(&parser.Permissions{Deny: []string{rule}}, nil))
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("deny %q: expected one error, got %+v", rule, f)
			continue
		}
		if !strings.Contains(f[0].Message, "<U+") {
			t.Errorf("deny %q: message should show where the character is: %s", rule, f[0].Message)
		}
	}
}

func TestCFG111_Severities(t *testing.T) {
	p := &parser.Permissions{
		Allow: []string{"Bash(np\u200bm test:*)"},
		Ask:   []string{"Bash(git pu\u200bsh:*)"},
		Deny:  []string{"Bash(curl:*)"},
	}
	hooks := map[string][]parser.HookGroup{"PreToolUse": {{Matcher: "Ba\u200bsh"}, {Matcher: "Write"}}}
	got := map[string]finding.Severity{}
	for _, f := range CFG111.Check(permTarget(p, hooks)) {
		got[strings.SplitN(f.Message, " \"", 2)[0]] = f.Severity
	}
	want := map[string]finding.Severity{
		"permissions.allow entry":  finding.Info,
		"permissions.ask entry":    finding.Error,
		"hooks.PreToolUse matcher": finding.Error,
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %v, want %v", k, got[k], v)
		}
	}
}

// Ordinary rules, including non-ASCII ones, are silent.
func TestCFG111_Clean(t *testing.T) {
	p := &parser.Permissions{
		Allow: []string{"Bash(npm run test:*)", "Read(./docs/**)", "Edit(./übersetzung/**)", "WebFetch(domain:例え.jp)"},
		Deny:  []string{"Read(./.env)", "Bash(rm -rf:*)"},
	}
	hooks := map[string][]parser.HookGroup{"PostToolUse": {{Matcher: "Edit|Write"}, {Matcher: ""}}}
	if f := CFG111.Check(permTarget(p, hooks)); len(f) != 0 {
		t.Errorf("expected nothing, got %+v", f)
	}
	if f := CFG111.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected nothing without settings, got %+v", f)
	}
}

// Rules Claude Code saves itself keep their line breaks and emoji; neither is a
// hidden character.
func TestCFG111_SavedMultilineRules(t *testing.T) {
	p := &parser.Permissions{Allow: []string{
		"Bash(git commit -m \"$(cat <<'EOF'\nfeat: add things\n\n- one\n\tdetail\r\nEOF\n)\")",
		"Bash(git commit -m \"ship it 👨\u200d💻\")",
	}}
	if f := CFG111.Check(permTarget(p, nil)); len(f) != 0 {
		t.Errorf("expected nothing, got %+v", f)
	}
	// A joiner that does not sit between emoji is still reported.
	f := CFG111.Check(permTarget(&parser.Permissions{Deny: []string{"Bash(cu\u200drl:*)"}}, nil))
	if len(f) != 1 {
		t.Errorf("a stray joiner must be reported, got %+v", f)
	}
}
