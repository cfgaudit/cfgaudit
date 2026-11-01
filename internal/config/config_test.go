// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

func parseT(t *testing.T, yml string) *Config {
	t.Helper()
	c, err := parse([]byte(yml), "test")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return c
}

func TestRuleConfig_FlatOff(t *testing.T) {
	c := parseT(t, "rules:\n  CFG003: off\n")
	if c.RuleEnabled("CFG003") {
		t.Errorf("CFG003 should be disabled")
	}
	if !c.RuleEnabled("CFG001") {
		t.Errorf("unlisted rule should stay enabled")
	}
}

func TestRuleConfig_NestedSeverityOverride(t *testing.T) {
	c := parseT(t, "rules:\n  CFG004:\n    severity: warn\n")
	in := []finding.Finding{{RuleID: "CFG004", Severity: finding.Error}}
	out := c.PostProcess(in, ".")
	if len(out) != 1 || out[0].Severity != finding.Warn {
		t.Fatalf("expected severity overridden to warn, got %+v", out)
	}
}

func TestRuleConfig_ScalarSeverityForm(t *testing.T) {
	c := parseT(t, "rules:\n  CFG004: info\n")
	out := c.PostProcess([]finding.Finding{{RuleID: "CFG004", Severity: finding.Error}}, ".")
	if out[0].Severity != finding.Info {
		t.Errorf("expected scalar severity override to info, got %s", out[0].Severity)
	}
}

func TestMinSeverity_FiltersBelowThreshold(t *testing.T) {
	c := parseT(t, "min-severity: warn\n")
	in := []finding.Finding{
		{RuleID: "A", Severity: finding.Info},
		{RuleID: "B", Severity: finding.Warn},
		{RuleID: "C", Severity: finding.Error},
	}
	out := c.PostProcess(in, ".")
	if len(out) != 2 {
		t.Fatalf("expected info dropped, got %d: %+v", len(out), out)
	}
}

func TestExcludePaths(t *testing.T) {
	c := parseT(t, "exclude-paths:\n  - vendor/\n  - \"**/.claude/settings.local.json\"\n")
	dir := "/proj"
	in := []finding.Finding{
		{RuleID: "A", File: filepath.Join(dir, "vendor", "x", ".claude", "settings.json")},
		{RuleID: "B", File: filepath.Join(dir, "sub", ".claude", "settings.local.json")},
		{RuleID: "C", File: filepath.Join(dir, ".claude", "settings.json")},
	}
	out := c.PostProcess(in, dir)
	if len(out) != 1 || out[0].RuleID != "C" {
		t.Fatalf("expected only C to survive, got %+v", out)
	}
}

func TestExitCode(t *testing.T) {
	errF := []finding.Finding{{Severity: finding.Error}}
	warnF := []finding.Finding{{Severity: finding.Warn}}

	if got := (*Config)(nil).ExitCode(errF); got != 1 {
		t.Errorf("nil config + error → 1, got %d", got)
	}
	if got := (*Config)(nil).ExitCode(warnF); got != 0 {
		t.Errorf("nil config + warn → 0, got %d", got)
	}
	if got := parseT(t, "strict: true\n").ExitCode(warnF); got != 1 {
		t.Errorf("strict + warn → 1, got %d", got)
	}
	if got := parseT(t, "no-exit-codes: true\n").ExitCode(errF); got != 0 {
		t.Errorf("no-exit-codes + error → 0, got %d", got)
	}
}

func TestNilConfig_Inert(t *testing.T) {
	var c *Config
	if !c.RuleEnabled("CFG001") {
		t.Errorf("nil config must enable all rules")
	}
	in := []finding.Finding{{RuleID: "X", Severity: finding.Warn}}
	if out := c.PostProcess(in, "."); len(out) != 1 {
		t.Errorf("nil config must not filter, got %+v", out)
	}
}

func TestDiscover_NoFile(t *testing.T) {
	c, path, err := Discover(t.TempDir())
	if err != nil || c != nil || path != "" {
		t.Errorf("expected no config discovered, got c=%v path=%q err=%v", c, path, err)
	}
}

func TestDiscover_FindsFile(t *testing.T) {
	dir := t.TempDir()
	if err := writeFile(filepath.Join(dir, ".cfgaudit.yml"), "min-severity: error\n"); err != nil {
		t.Fatal(err)
	}
	c, path, err := Discover(dir)
	if err != nil || c == nil {
		t.Fatalf("expected config discovered, got c=%v err=%v", c, err)
	}
	if filepath.Base(path) != ".cfgaudit.yml" {
		t.Errorf("unexpected path %q", path)
	}
}

func TestPolicy_Parse(t *testing.T) {
	c := parseT(t, "policy:\n  require-deny:\n    - \"Bash(git commit:*)\"\n  forbid-allow:\n    - \"Bash(git commit:*)\"\n    - \"Bash(curl:*)\"\n")
	if !c.Policy.Configured() {
		t.Fatal("expected policy configured")
	}
	if len(c.Policy.RequireDeny) != 1 || len(c.Policy.ForbidAllow.Claude) != 2 {
		t.Errorf("unexpected policy: %+v", c.Policy)
	}
}

func TestPolicy_AbsentNotConfigured(t *testing.T) {
	if parseT(t, "min-severity: warn\n").Policy.Configured() {
		t.Error("policy should be unconfigured when absent")
	}
}

func TestShellCheckExclude_Normalized(t *testing.T) {
	c := parseT(t, "shellcheck: true\nshellcheck-exclude: [SC2086, sc2034, \" 1090 \"]\n")
	want := []string{"SC2086", "SC2034", "SC1090"}
	got := c.ShellCheckExcludes()
	if len(got) != len(want) {
		t.Fatalf("ShellCheckExcludes() = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ShellCheckExcludes()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestShellCheckExclude_RejectsNonCodes(t *testing.T) {
	for _, code := range []string{"2086x", "SC208", "SC20860", "CFG045", "SC-2086", ""} {
		_, err := parse([]byte("shellcheck-exclude: [\""+code+"\"]\n"), "test.yml")
		if err == nil {
			t.Errorf("shellcheck-exclude %q was accepted", code)
			continue
		}
		if !strings.Contains(err.Error(), "test.yml") || !strings.Contains(err.Error(), "shellcheck-exclude") {
			t.Errorf("error for %q does not name the file and key: %v", code, err)
		}
	}
}

func TestShellCheckExclude_AbsentOrNil(t *testing.T) {
	if got := parseT(t, "shellcheck: true\n").ShellCheckExcludes(); len(got) != 0 {
		t.Errorf("no shellcheck-exclude key gave %q", got)
	}
	var c *Config
	if got := c.ShellCheckExcludes(); got != nil {
		t.Errorf("nil config gave %q", got)
	}
}

func TestRuleConfig_RejectsOtherNodeKinds(t *testing.T) {
	for _, yml := range []string{
		"rules:\n  CFG004: [off]\n",
		"rules:\n  CFG004:\n    off: [true]\n",
	} {
		if _, err := parse([]byte(yml), "test"); err == nil {
			t.Errorf("parse(%q): expected an error", yml)
		}
	}
}

func TestParse_ContentPaths(t *testing.T) {
	c, err := parse([]byte("content-paths:\n  - README.md\n  - docs/**/*.md\n"), "c.yml")
	if err != nil {
		t.Fatal(err)
	}
	if got := c.ContentPathGlobs(); len(got) != 2 || got[1] != "docs/**/*.md" {
		t.Errorf("ContentPathGlobs = %q", got)
	}
	if (*Config)(nil).ContentPathGlobs() != nil {
		t.Error("a nil config has no content paths")
	}
	if !MatchGlob("docs/**/*.md", "docs/a/b.md") || MatchGlob("docs/**/*.md", "src/a.md") {
		t.Error("MatchGlob does not follow the exclude-paths syntax")
	}
}

func TestParse_InvalidYAML(t *testing.T) {
	_, err := parse([]byte("rules: [\n"), "bad.yml")
	if err == nil || !strings.Contains(err.Error(), "bad.yml") {
		t.Fatalf("expected a parse error naming the file, got %v", err)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "custom.yml")
	if err := writeFile(p, "strict: true\n"); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil || c == nil || !c.Strict {
		t.Fatalf("Load(%s) = %+v, %v; want strict config", p, c, err)
	}
	if _, err := Load(filepath.Join(dir, "missing.yml")); err == nil {
		t.Error("Load of a missing file must fail")
	}
}

func TestDiscover_Errors(t *testing.T) {
	// A directory where the config file is expected is no config (#828): the
	// scan runs with the defaults, which are the strictest settings, instead of
	// stopping.
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".cfgaudit.yml"), 0o750); err != nil {
		t.Fatal(err)
	}
	if c, p, err := Discover(dir); err != nil || c != nil || p != "" {
		t.Errorf("a .cfgaudit.yml directory should read as no config, got %v, %q, %v", c, p, err)
	}

	dir = t.TempDir()
	if err := writeFile(filepath.Join(dir, ".cfgaudit.yml"), "rules: [\n"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Discover(dir); err == nil {
		t.Error("expected an error for an unparseable .cfgaudit.yml")
	}
}

func TestPostProcess_SeverityOverrides(t *testing.T) {
	c := parseT(t, "rules:\n  A: error\n")
	out := c.PostProcess([]finding.Finding{{RuleID: "A", Severity: finding.Info}}, ".")
	if out[0].Severity != finding.Error {
		t.Errorf("A: want error, got %s", out[0].Severity)
	}
	// parse rejects an invalid severity (#1051); a Config built in code that
	// carries one still leaves the finding unchanged.
	c = &Config{Rules: map[string]RuleConfig{"B": {Severity: "loud"}}}
	out = c.PostProcess([]finding.Finding{{RuleID: "B", Severity: finding.Warn}}, ".")
	if out[0].Severity != finding.Warn {
		t.Errorf("B: an unknown severity must leave the finding unchanged, got %s", out[0].Severity)
	}
}

func TestExcludePaths_RelativeFileOutsideDir(t *testing.T) {
	// filepath.Rel cannot relate a relative file to an absolute dir; the file
	// path is then matched as given.
	c := parseT(t, "exclude-paths:\n  - \"docs/*.json\"\n")
	out := c.PostProcess([]finding.Finding{{RuleID: "A", File: "docs/a.json"}}, "/proj")
	if len(out) != 0 {
		t.Fatalf("expected the finding excluded, got %+v", out)
	}
}

func TestMatchGlob(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"a?c.json", "abc.json", true},
		{"a?c.json", "a/c.json", false},
		{"**", "x/y/z", true},
		{"src/**.json", "src/a/b.json", true},
		{"src/**/b.json", "src/a/b.json", true},
		{"*.json", "a/b.json", false},
		{"vendor/", "vendor", true},
		{"vendor/", "vendored/x", false},
	}
	for _, c := range cases {
		if got := matchGlob(c.pattern, c.path); got != c.want {
			t.Errorf("matchGlob(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

// A config document the YAML decoder panics on is a parse error (#846).
func TestParse_DecoderPanic(t *testing.T) {
	if _, err := parse([]byte("? -\n? <<\n"), "test"); err == nil {
		t.Fatal("expected a parse error")
	}
}

// The rows of #1051: each config the decoder used to accept without a word is
// rejected, naming the file, the line and the key.
func TestParse_RejectsUnknownKeysAndInvalidValues(t *testing.T) {
	cases := []struct{ yaml, want string }{
		{"stirct: true\n", `test:1: unknown key "stirct"`},
		{"only: [CFG006]\n", `test:1: unknown key "only"`},
		{"min-severity: bogus\n", `test:1: min-severity: "bogus" is not a severity`},
		{"rules:\n  CFG001:\n    severity: bogus\n", `test:3: rules.CFG001.severity: "bogus" is not a severity`},
		{"rules:\n  CFG006: {of: true}\n", `test:2: unknown key "rules.CFG006.of"`},
		{"rules:\n  CFG006: false\n", `test:2: rules.CFG006: "false" is neither off nor a severity`},
		{"policy:\n  require-deny: [x]\n  forbid-alow: [y]\n", `test:3: unknown key "policy.forbid-alow"`},
		{"strict: true\nexclude-path: [vendor/]\n", `test:2: unknown key "exclude-path"`},
	}
	for _, tc := range cases {
		_, err := parse([]byte(tc.yaml), "test")
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("parse(%q) = %v, want an error containing %q", tc.yaml, err, tc.want)
		}
	}
}

// Every documented key keeps parsing, in both rule override forms, and so do
// an empty file, a merge key and an alias.
func TestParse_AcceptsEveryKey(t *testing.T) {
	valid := `rules:
  CFG003: off
  CFG004: warn
  CFG005: {severity: INFO}
  CFG006: {off: true}
  CFG007: {off: false, severity: error}
min-severity: Warn
strict: true
no-exit-codes: false
exclude-paths: [vendor/]
policy:
  require-deny: ["Bash(rm -rf *)"]
  forbid-allow: ["Bash(curl *)"]
shellcheck: true
shellcheck-exclude: [SC2086]
content-paths: [README.md]
`
	c, err := parse([]byte(valid), "test")
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if !c.Strict || c.RuleEnabled("CFG003") || c.Rules["CFG005"].Severity != "INFO" || c.MinSeverity != "Warn" {
		t.Errorf("valid config decoded wrong: %+v", c)
	}
	for _, doc := range []string{"", "# only a comment\n", "rules:\n  CFG001: &w warn\n  CFG002: *w\n", "rules:\n  <<: {CFG001: off}\n"} {
		if _, err := parse([]byte(doc), "test"); err != nil {
			t.Errorf("parse(%q) = %v, want no error", doc, err)
		}
	}
}

// A rule ID no rule reports is a warning, not an error, so a config written
// for a newer cfgaudit still loads; UnknownRuleIDs names it with its line.
func TestUnknownRuleIDs(t *testing.T) {
	c := parseT(t, "strict: true\nrules:\n  CFG999: off\n  CFG001: warn\n  CFG0O6: off\n")
	got := c.UnknownRuleIDs(map[string]bool{"CFG001": true})
	want := []UnknownRule{{"CFG999", 3}, {"CFG0O6", 5}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("UnknownRuleIDs = %v, want %v", got, want)
	}
	if (*Config)(nil).UnknownRuleIDs(nil) != nil {
		t.Error("nil config must report no unknown rules")
	}
}

// The agent-neutral policy parses next to the Claude Code lists, and
// forbid-allow takes either form (#1081).
func TestPolicy_Neutral(t *testing.T) {
	c := parseT(t, `policy:
  deny:
    commands: ["git push"]
    read: ["**/.env", "~/.ssh/**"]
    write: ["src/generated/**"]
    fetch: ["*.example.com", "example.org"]
    mcp-tools: ["github:delete_*", "linear:*"]
  forbid-allow:
    commands: [curl]
    mcp-tools: ["github:create_issue"]
  agents: [claude-code, devin, zed, continue]
`)
	p := c.Policy
	if !p.Configured() || len(p.Deny.Read) != 2 || len(p.Deny.MCPTools) != 2 || len(p.ForbidAllow.Commands) != 1 ||
		len(p.ForbidAllow.MCPTools) != 1 || len(p.ForbidAllow.Claude) != 0 || len(p.Agents) != 4 {
		t.Fatalf("unexpected policy: %+v", p)
	}
	if !parseT(t, "policy:\n  forbid-allow:\n    commands: [curl]\n").Policy.Configured() {
		t.Error("a neutral forbid-allow alone should count as a policy")
	}
	if l := parseT(t, "policy:\n  forbid-allow: [\"Bash(curl:*)\"]\n").Policy.ForbidAllow; len(l.Claude) != 1 || !l.Empty() {
		t.Errorf("list form: got %+v", l)
	}
}

// A neutral entry the category cannot hold, an unknown category, and an agent
// cfgaudit cannot check yet are rejected with the line (#1081).
func TestPolicy_NeutralRejects(t *testing.T) {
	cases := []struct{ yaml, want string }{
		{"policy:\n  deny:\n    comands: [x]\n", `test:3: unknown key "policy.deny.comands"`},
		{"policy:\n  forbid-allow:\n    read: [x]\n", `test:3: unknown key "policy.forbid-allow.read"`},
		{"policy:\n  agents: [claude-code, cursor]\n", `test:2: policy.agents: "cursor" is not an agent the policy can check yet`},
		{"policy:\n  deny:\n    commands: [\"Bash(git push:*)\"]\n", `policy.deny.commands: "Bash(git push:*)" is not a plain command`},
		{"policy:\n  deny:\n    commands: [\"\"]\n", `policy.deny.commands: "" is empty`},
		{"policy:\n  deny:\n    read: [/etc/passwd]\n", `policy.deny.read: "/etc/passwd" starts with /`},
		{"policy:\n  deny:\n    fetch: [\"https://example.com\"]\n", `policy.deny.fetch: "https://example.com" is not a domain`},
		{"policy:\n  deny:\n    fetch: [localhost]\n", `policy.deny.fetch: "localhost" is not a domain`},
		{"policy:\n  deny:\n    mcp-tools: [github]\n", `policy.deny.mcp-tools: "github" is not server:tool`},
		{"policy:\n  deny:\n    mcp-tools: [\"git*:x\"]\n", `is not server:tool`},
		{"policy:\n  forbid-allow:\n    mcp-tools: [\"github:*_repo\"]\n", `is not server:tool`},
	}
	for _, tc := range cases {
		_, err := parse([]byte(tc.yaml), "test")
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("parse(%q) = %v, want an error containing %q", tc.yaml, err, tc.want)
		}
	}
}
