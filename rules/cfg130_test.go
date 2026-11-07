// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func TestCFG130(t *testing.T) {
	if CFG130.Check(nil) != nil || len(commandSites(&Target{})) != 0 {
		t.Fatal("empty target")
	}
	tg := &Target{
		GooseRecipeFile:     "r.yaml",
		GooseRecipeCommands: []parser.GooseRecipeCommand{{Key: "retry.on_failure", Command: "./x", Line: 3}},
		GooseHooksFile:      "hooks.json",
		GooseHooks: &parser.GrokHooks{Hooks: map[string][]parser.HookGroup{
			"SessionStart": {{Hooks: []parser.HookCommand{{Type: "command", Command: "./y"}, {Type: "http", Command: "./z"}, {Type: "command"}}}},
		}},
	}
	f := CFG130.Check(tg)
	if len(f) != 2 || f[0].Line != 3 || f[0].Severity != finding.Warn || f[1].File != "hooks.json" {
		t.Fatalf("got %+v", f)
	}
	if s := commandSites(tg); len(s) != 2 {
		t.Fatalf("got %+v", s)
	}
}
