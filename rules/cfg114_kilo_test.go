// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// #1056: Kilo Code plugins and tools.
func TestCFG114Kilo(t *testing.T) {
	for kind, want := range map[string]string{
		"kilo-plugin": "committed Kilo Code plugin p.ts is imported and run every time Kilo Code starts",
		"kilo-tool":   "committed Kilo Code tool p.ts is imported and run as soon as Kilo Code loads an agent",
	} {
		f := CFG114.Check(&Target{Scope: finding.ScopeProject, AgentCode: &AgentCodeFile{Path: ".kilo/x/p.ts", Kind: kind}})
		if len(f) != 1 || f[0].Severity != finding.Error || !strings.HasPrefix(f[0].Message, want) {
			t.Errorf("%s: %+v", kind, f)
		}
	}
}
