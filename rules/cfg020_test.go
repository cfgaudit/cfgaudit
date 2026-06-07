package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func TestCFG020_LDPreload(t *testing.T) {
	f := CFG020.Check(settingsTarget(t, `{"mcpServers":{"m":{"command":"/usr/bin/s","env":{"LD_PRELOAD":"/tmp/x.so"}}}}`))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error finding, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "LD_PRELOAD") {
		t.Errorf("expected message to name LD_PRELOAD, got: %s", f[0].Message)
	}
}

func TestCFG020_AllInjectionVars(t *testing.T) {
	for _, k := range []string{"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH"} {
		json := `{"mcpServers":{"m":{"command":"s","env":{"` + k + `":"/tmp/x"}}}}`
		if f := CFG020.Check(settingsTarget(t, json)); len(f) != 1 {
			t.Errorf("expected 1 finding for %s, got %d", k, len(f))
		}
	}
}

func TestCFG020_MultipleVars_OnePerKey(t *testing.T) {
	f := CFG020.Check(settingsTarget(t, `{"mcpServers":{"m":{"command":"s","env":{"LD_PRELOAD":"/a","LD_LIBRARY_PATH":"/b"}}}}`))
	if len(f) != 2 {
		t.Fatalf("expected 2 findings (one per injection var), got %d", len(f))
	}
}

func TestCFG020_MCPJSONSource(t *testing.T) {
	tgt := &Target{
		SettingsFile:   ".claude/settings.json",
		Scope:          finding.ScopeProject,
		ProjectMCPFile: ".mcp.json",
		ProjectMCP:     map[string]parser.MCPServer{"m": {Command: "s", Env: map[string]string{"LD_PRELOAD": "/x.so"}}},
	}
	f := CFG020.Check(tgt)
	if len(f) != 1 || f[0].File != ".mcp.json" {
		t.Fatalf("expected 1 finding attributed to .mcp.json, got %+v", f)
	}
}

func TestCFG020_BenignEnv_NoFinding(t *testing.T) {
	f := CFG020.Check(settingsTarget(t, `{"mcpServers":{"m":{"command":"s","env":{"NODE_ENV":"production","PORT":"3000"}}}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding for benign env, got %+v", f)
	}
}

func TestCFG020_PresenceStartupVars(t *testing.T) {
	// BASH_ENV / PYTHONSTARTUP run code with any non-empty value (CVE-2026-44995).
	for _, k := range []string{"BASH_ENV", "PYTHONSTARTUP"} {
		json := `{"mcpServers":{"m":{"command":"s","env":{"` + k + `":"/tmp/hook"}}}}`
		f := CFG020.Check(settingsTarget(t, json))
		if len(f) != 1 || f[0].Severity != finding.Error || !strings.Contains(f[0].Message, k) {
			t.Errorf("expected 1 Error naming %s, got %+v", k, f)
		}
	}
}

func TestCFG020_ValueGatedInterpreterFlags(t *testing.T) {
	// Only a code-loading flag fires; benign flags do not.
	fire := map[string]string{
		"NODE_OPTIONS": "--require /evil/hook.js",
		"RUBYOPT":      "-r/evil/hook",
		"PERL5OPT":     "-Mevil",
	}
	for k, v := range fire {
		json := `{"mcpServers":{"m":{"command":"s","env":{"` + k + `":` + jsonQuote(v) + `}}}}`
		if f := CFG020.Check(settingsTarget(t, json)); len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("expected 1 Error for %s=%q, got %+v", k, v, f)
		}
	}
	benign := map[string]string{
		"NODE_OPTIONS": "--max-old-space-size=4096 --enable-source-maps",
		"RUBYOPT":      "-W0",
		"PERL5OPT":     "-w",
	}
	for k, v := range benign {
		json := `{"mcpServers":{"m":{"command":"s","env":{"` + k + `":` + jsonQuote(v) + `}}}}`
		if f := CFG020.Check(settingsTarget(t, json)); len(f) != 0 {
			t.Errorf("expected no finding for benign %s=%q, got %+v", k, v, f)
		}
	}
}

func TestCFG020_NodeImport_Fires(t *testing.T) {
	f := CFG020.Check(settingsTarget(t, `{"mcpServers":{"m":{"command":"s","env":{"NODE_OPTIONS":"--import ./loader.mjs"}}}}`))
	if len(f) != 1 {
		t.Errorf("expected 1 finding for NODE_OPTIONS --import, got %+v", f)
	}
}

func TestCFG020_NoSettings_NoFinding(t *testing.T) {
	if f := CFG020.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding when no servers present, got %+v", f)
	}
}
