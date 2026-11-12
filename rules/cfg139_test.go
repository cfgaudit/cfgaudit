// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func kimiLocalTarget(rules []parser.KimiPermissionRule, dirs ...string) *Target {
	c := &parser.KimiLocalConfig{}
	c.Permission.Rules = rules
	c.Workspace.AdditionalDir = dirs
	return &Target{Scope: finding.ScopeProject, KimiLocal: c, KimiLocalFile: ".kimi-code/local.toml"}
}

func allow(p string) parser.KimiPermissionRule {
	return parser.KimiPermissionRule{Decision: "allow", Pattern: p}
}

func TestCFG139_AllowSeverity(t *testing.T) {
	for p, want := range map[string]finding.Severity{
		"Read":                     finding.Error,
		"Write":                    finding.Error,
		"Edit(**)":                 finding.Error,
		"Bash":                     finding.Error,
		"Bash(*)":                  finding.Error,
		"*":                        finding.Error,
		"Read(**/.env)":            finding.Error,
		"Read(~/.ssh/**)":          finding.Error,
		"Write(.git/hooks/*)":      finding.Error,
		"Read(**/credentials*)":    finding.Error,
		"Bash(sudo*)":              finding.Warn,
		"Bash(curl *)":             finding.Warn,
		"Bash(/usr/bin/docker *)":  finding.Warn,
		"Bash(npm test*)":          "",
		"Bash(git status)":         "",
		"Read(src/**)":             "",
		"Read(.env.example)":       "",
		"Read(config/.env.sample)": "",
		"Grep":                     "",
		"WebSearch":                "",
		"Bash()":                   finding.Error,
		"Bash(":                    "",
	} {
		f := CFG139.Check(kimiLocalTarget([]parser.KimiPermissionRule{allow(p)}))
		switch {
		case want == "" && len(f) != 0:
			t.Errorf("%s: want none, got %+v", p, f)
		case want != "" && (len(f) != 1 || f[0].Severity != want):
			t.Errorf("%s: want %s, got %+v", p, want, f)
		}
	}
}

// Deny and ask rules narrow, so they are never reported.
func TestCFG139_DenyAsk(t *testing.T) {
	f := CFG139.Check(kimiLocalTarget([]parser.KimiPermissionRule{
		{Decision: "deny", Pattern: "Bash"}, {Decision: "ask", Pattern: "*"},
	}))
	if len(f) != 0 {
		t.Errorf("got %+v", f)
	}
}

func TestCFG139_AdditionalDir(t *testing.T) {
	f := CFG139.Check(kimiLocalTarget(nil, "/srv/shared", "~", "~/notes", "..", "../other", `C:\work\x`, "docs", "./sub", "", "a/../b"))
	if len(f) != 6 {
		t.Fatalf("want 6 info, got %+v", f)
	}
	for _, x := range f {
		if x.Severity != finding.Info {
			t.Errorf("want info: %+v", x)
		}
	}
	if CFG139.ID() != "CFG139" || CFG139.Check(nil) != nil || CFG139.Check(&Target{}) != nil {
		t.Error("ID or empty target")
	}
	if kimiFirstWord("*") != "" || kimiToolLabel("*") != "tool" {
		t.Error("helpers")
	}
}
