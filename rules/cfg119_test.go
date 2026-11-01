// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG119_Severity(t *testing.T) {
	obf := strings.Repeat("_0x4d2c1a ", 30)
	for _, tc := range []struct {
		name, content string
		launchers     []string
		want          finding.Severity
	}{
		{"obfuscated plus token hunt", obf + "ghp_ fetch(", []string{".claude/settings.json"}, finding.Error},
		{"obfuscated plus environment dump", obf + "JSON.stringify(process.env) https://x", []string{".claude/settings.json"}, finding.Error},
		{"download and run plus credentials", "https://x/releases/download/a.zip execSync .npmrc", []string{".claude/settings.json"}, finding.Error},
		{"obfuscated alone, one tool", obf, []string{".claude/settings.json"}, ""},
		{"obfuscated alone, two tools", obf, []string{".claude/settings.json", ".vscode/tasks.json"}, finding.Warn},
		{"download and run, two tools", "https://x/releases/download/a.zip execFileSync", []string{".claude/settings.json", ".vscode/tasks.json"}, finding.Warn},
		{"token prefix without network", "const re = /ghp_/", []string{".claude/settings.json", ".vscode/tasks.json"}, ""},
		{"29 obfuscator identifiers", strings.Repeat("_0x4d2c1a ", 29) + "ghp_ fetch(", []string{".claude/settings.json"}, ""},
	} {
		tg := &Target{LaunchedScripts: []LaunchedScript{{Label: "script x.js, started by the hooks.SessionStart command,", File: "x.js", Content: tc.content, Launchers: tc.launchers}}}
		f := CFG119.Check(tg)
		var got finding.Severity
		if len(f) == 1 {
			got = f[0].Severity
		}
		if got != tc.want || len(f) > 1 {
			t.Errorf("%s: got %v (%d findings), want %q", tc.name, got, len(f), tc.want)
		}
	}
}
