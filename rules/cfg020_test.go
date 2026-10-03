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

// #610: the four variables added to the shared list, with their value gates.
func TestCFG020_AddedVars(t *testing.T) {
	cases := []struct {
		key, value string
		want       int
	}{
		{"DOTNET_STARTUP_HOOKS", "/tmp/hook.dll", 1},
		{"JAVA_TOOL_OPTIONS", "-javaagent:/tmp/a.jar", 1},
		{"JAVA_TOOL_OPTIONS", "-Xmx2g -Dfile.encoding=UTF-8", 0},
		{"JAVA_TOOL_OPTIONS", "-XX:OnOutOfMemoryError=/tmp/x.sh", 1},
		{"_JAVA_OPTIONS", "-agentpath:/tmp/a.so", 1},
		{"JDK_JAVA_OPTIONS", "-Xbootclasspath/a:/tmp/x.jar", 1},
		{"GIT_SSH_COMMAND", "ssh -i ./deploy_key -o IdentitiesOnly=yes", 0},
		{"GIT_SSH_COMMAND", "/usr/bin/ssh -o ProxyCommand=/tmp/x.sh", 1},
		{"GIT_SSH_COMMAND", "./tools/fake-ssh", 1},
	}
	for _, c := range cases {
		json := `{"mcpServers":{"m":{"command":"s","env":{"` + c.key + `":"` + c.value + `"}}}}`
		if f := CFG020.Check(settingsTarget(t, json)); len(f) != c.want {
			t.Errorf("%s=%q: expected %d finding(s), got %+v", c.key, c.value, c.want, f)
		}
	}
}

// GIT_CONFIG_KEY_<n> counts only when GIT_CONFIG_COUNT makes the pair live and
// the key names a command.
func TestCFG020_GitConfigPairs(t *testing.T) {
	cases := []struct {
		env  string
		want int
	}{
		{`"GIT_CONFIG_COUNT":"1","GIT_CONFIG_KEY_0":"core.fsmonitor","GIT_CONFIG_VALUE_0":"x"`, 1},
		{`"GIT_CONFIG_COUNT":"1","GIT_CONFIG_KEY_0":"alias.st","GIT_CONFIG_VALUE_0":"!x"`, 1},
		{`"GIT_CONFIG_KEY_0":"core.fsmonitor","GIT_CONFIG_VALUE_0":"x"`, 0},
		{`"GIT_CONFIG_COUNT":"1","GIT_CONFIG_KEY_1":"core.fsmonitor","GIT_CONFIG_VALUE_1":"x"`, 0},
		{`"GIT_CONFIG_COUNT":"1","GIT_CONFIG_KEY_0":"user.name","GIT_CONFIG_VALUE_0":"x"`, 0},
	}
	for _, c := range cases {
		json := `{"mcpServers":{"m":{"command":"s","env":{` + c.env + `}}}}`
		if f := CFG020.Check(settingsTarget(t, json)); len(f) != c.want {
			t.Errorf("%s: expected %d finding(s), got %+v", c.env, c.want, f)
		}
	}
}
