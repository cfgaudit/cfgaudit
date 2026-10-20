package config

import (
	"os"
	"path/filepath"
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
	if len(c.Policy.RequireDeny) != 1 || len(c.Policy.ForbidAllow) != 2 {
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
	// A directory where the config file is expected is a read error, not "no config".
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".cfgaudit.yml"), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Discover(dir); err == nil {
		t.Error("expected an error when .cfgaudit.yml is a directory")
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
	c := parseT(t, "rules:\n  A: error\n  B: loud\n")
	out := c.PostProcess([]finding.Finding{
		{RuleID: "A", Severity: finding.Info},
		{RuleID: "B", Severity: finding.Warn},
	}, ".")
	if out[0].Severity != finding.Error {
		t.Errorf("A: want error, got %s", out[0].Severity)
	}
	if out[1].Severity != finding.Warn {
		t.Errorf("B: an unknown severity must leave the finding unchanged, got %s", out[1].Severity)
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
