// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG116(t *testing.T) {
	tests := []struct {
		name  string
		t     *Target
		count int
	}{
		{"home import", &Target{Scope: finding.ScopeProject, InstructionFile: "CLAUDE.md", ExternalImports: []string{"~/.aws/credentials"}}, 1},
		{"two imports", &Target{Scope: finding.ScopeProject, InstructionFile: ".claude/rules/a.md", ExternalImports: []string{"../x.md", "/etc/x.md"}}, 2},
		{"imported file", &Target{Scope: finding.ScopeProject, InstructionFile: "docs/notes.md", ImportChain: []string{"CLAUDE.md", "docs/notes.md"}, ExternalImports: []string{"~/x.md"}}, 1},
		{"no external imports", &Target{Scope: finding.ScopeProject, InstructionFile: "CLAUDE.md"}, 0},
		{"CLAUDE.local.md", &Target{Scope: finding.ScopeProject, InstructionFile: "CLAUDE.local.md", ExternalImports: []string{"~/.claude/prefs.md"}}, 0},
		{"user scope", &Target{Scope: finding.ScopeUser, InstructionFile: "CLAUDE.md", ExternalImports: []string{"~/x.md"}}, 0},
		{"nil target", nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CFG116.Check(tt.t)
			if len(got) != tt.count {
				t.Fatalf("want %d findings, got %+v", tt.count, got)
			}
			for i, f := range got {
				if f.Severity != finding.Warn || f.File != tt.t.InstructionFile || !strings.Contains(f.Message, `"@`+tt.t.ExternalImports[i]+`"`) {
					t.Errorf("unexpected finding %+v", f)
				}
			}
		})
	}
}
