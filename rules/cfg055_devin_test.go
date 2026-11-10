// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func devinPluginTarget(t *testing.T, entries string) *Target {
	t.Helper()
	var raw []json.RawMessage
	if err := json.Unmarshal([]byte(entries), &raw); err != nil {
		t.Fatal(err)
	}
	return &Target{Scope: finding.ScopeProject, Devin: &parser.DevinConfig{RequiredPlugins: raw}, DevinFile: ".devin/config.json"}
}

// #1603: a repo-level requiredPlugins entry installs silently.
func TestCFG055DevinRequiredPlugins(t *testing.T) {
	f := CFG055.Check(devinPluginTarget(t, `[
		"acme/secure-base",
		{"source": "github", "repo": "acme/audit-logging"},
		{"source": "url", "url": "https://gitlab.example/acme/extra.git"},
		"./tools/devin-plugin",
		"/opt/plugins/x",
		"~/plugins/y",
		{"source": "local", "path": "../outside"},
		{"source": "git-subdir", "url": "https://github.com/acme/skills.git", "path": "plugins/ops"},
		42,
		{"source": "unknown"}
	]`))
	want := []finding.Severity{finding.Warn, finding.Warn, finding.Warn, finding.Warn, finding.Error, finding.Error, finding.Error, finding.Warn}
	if len(f) != len(want) {
		t.Fatalf("got %d findings: %+v", len(f), f)
	}
	for i, s := range want {
		if f[i].Severity != s || f[i].Key != "requiredPlugins" {
			t.Errorf("finding %d: %+v", i, f[i])
		}
	}
	if !strings.Contains(f[0].Message, `installs the plugin "acme/secure-base"`) || !strings.Contains(f[4].Message, "outside the repository") ||
		!strings.Contains(f[7].Message, `"https://github.com/acme/skills.git#plugins/ops"`) {
		t.Errorf("messages: %s | %s", f[0].Message, f[4].Message)
	}
	user := devinPluginTarget(t, `["acme/x"]`)
	user.Scope = finding.ScopeUser
	if f := CFG055.Check(user); len(f) != 0 {
		t.Errorf("user scope: %+v", f)
	}
	if f := CFG055.Check(&Target{Devin: &parser.DevinConfig{}, DevinFile: ".devin/config.json"}); len(f) != 0 {
		t.Errorf("no plugins: %+v", f)
	}
}
