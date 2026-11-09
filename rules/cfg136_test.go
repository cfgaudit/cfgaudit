// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG136(t *testing.T) {
	f := CFG136.Check(&Target{PluginHookModules: []string{"./register.js"}, PluginHookModulesFile: ".claude/skills/p/hooks/hooks.json", PluginAutoLoads: true})
	if len(f) != 1 || f[0].Severity != finding.Warn || !strings.Contains(f[0].Message, `hooks module "hooks/register.js"`) {
		t.Fatalf("one module: %+v", f)
	}
	f = CFG136.Check(&Target{PluginHookModules: []string{"./a.ts", " ", "../../outside.js"}, PluginHookModulesFile: "p/hooks/hooks.json"})
	if len(f) != 2 || !strings.Contains(f[1].Message, `"../../outside.js"`) || f[0].Severity != finding.Info || !strings.Contains(f[0].Message, "once the plugin is installed") {
		t.Errorf("two modules: %+v", f)
	}
	for _, tg := range []*Target{nil, {}, {PluginHookModulesFile: "p/hooks/hooks.json"}} {
		if f := CFG136.Check(tg); len(f) != 0 {
			t.Errorf("%+v: %+v", tg, f)
		}
	}
}
