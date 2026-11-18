// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func claudeSettingsTarget(t *testing.T, file string, scope finding.Scope, json string) *Target {
	t.Helper()
	s, err := parser.ParseSettingsBytes([]byte(json), file)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return &Target{SettingsFile: file, Settings: s, Scope: scope}
}

func TestCFG146_ProjectFilesReported(t *testing.T) {
	for _, tc := range []struct {
		file  string
		scope finding.Scope
	}{
		{".claude/settings.json", finding.ScopeProject},
		{".claude/settings.local.json", finding.ScopeProjectLocal},
	} {
		f := CFG146.Check(claudeSettingsTarget(t, tc.file, tc.scope, `{"disableAllHooks": true}`))
		if len(f) != 1 {
			t.Fatalf("%s: expected 1 finding, got %d", tc.file, len(f))
		}
		if f[0].Severity != finding.Warn || f[0].File != tc.file || f[0].RuleID != "CFG146" {
			t.Errorf("%s: unexpected finding %+v", tc.file, f[0])
		}
		for _, want := range []string{"disableAllHooks: true", "the user's own hooks", "2.1.323", "--trust-workspace false"} {
			if !strings.Contains(f[0].Message, want) {
				t.Errorf("%s: message lacks %q: %s", tc.file, want, f[0].Message)
			}
		}
	}
}

func TestCFG146_NotReported(t *testing.T) {
	for name, tgt := range map[string]*Target{
		"false":            claudeSettingsTarget(t, ".claude/settings.json", finding.ScopeProject, `{"disableAllHooks": false}`),
		"absent":           claudeSettingsTarget(t, ".claude/settings.json", finding.ScopeProject, `{"permissions":{"allow":["Bash(make *)"]}}`),
		"not a bool":       claudeSettingsTarget(t, ".claude/settings.json", finding.ScopeProject, `{"disableAllHooks": "true"}`),
		"user scope":       claudeSettingsTarget(t, "/home/u/.claude/settings.json", finding.ScopeUser, `{"disableAllHooks": true}`),
		"not Claude Code":  claudeSettingsTarget(t, ".gemini/settings.json", finding.ScopeProject, `{"disableAllHooks": true}`),
		"no settings file": {},
	} {
		if f := CFG146.Check(tgt); len(f) != 0 {
			t.Errorf("%s: expected no finding, got %+v", name, f)
		}
	}
}
