// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// #1663: multi-segment TypeScript path aliases are not imports; absolute
// paths, files with an extension and credential paths still are.
func TestCFG116_PathAliases1663(t *testing.T) {
	for _, tt := range []struct {
		path     string
		reported bool
	}{
		{"/lib/utils", false},
		{"/components/ui/_", false},
		{"/composables/useMarkdown", false},
		{"/components/ui/*", false},
		{"/lib/utils/", false},
		{"/home/me/.ssh/config", true},
		{"/home/me/notes", true},
		{"/Users/me/notes", true},
		{"/etc/claude/rules", true},
		{"/lib/utils.md", true},
		{"/config/secrets", true},
		{"~/notes.md", true},
	} {
		t.Run(tt.path, func(t *testing.T) {
			got := CFG116.Check(&Target{Scope: finding.ScopeProject, InstructionFile: "CLAUDE.md", ExternalImports: []string{tt.path}})
			if (len(got) == 1) != tt.reported || len(got) > 1 {
				t.Errorf("@%s: want reported=%v, got %+v", tt.path, tt.reported, got)
			}
		})
	}
}
