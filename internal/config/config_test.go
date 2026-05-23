package config

import (
	"os"
	"path/filepath"
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
