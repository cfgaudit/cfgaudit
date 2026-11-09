// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// #1210: a path alias is not an import; a personal or workspace file is info;
// an absolute path and credentials stay warn.
func TestCFG116_Severity1210(t *testing.T) {
	for _, tc := range []struct {
		imp  string
		want finding.Severity // "" for no finding
	}{
		{"/actions", ""},
		{"/routes,", ""},
		{"/*", ""},
		{"/components.", ""},
		{"~/.claude/my-project-notes.md", finding.Info},
		{"../shared/team-conventions.md", finding.Info},
		{"/home/alice/notes.md", finding.Warn},
		{"/media/disk/notes.md", finding.Warn},
		{"~/.ssh/config", finding.Warn},
		{"~/.aws/credentials", finding.Warn},
		{"../.env", finding.Warn},
		{"~/keys/server.pem", finding.Warn},
	} {
		f := CFG116.Check(&Target{Scope: finding.ScopeProject, InstructionFile: "CLAUDE.md", ExternalImports: []string{tc.imp}})
		switch {
		case tc.want == "" && len(f) != 0:
			t.Errorf("%s: want no finding, got %+v", tc.imp, f)
		case tc.want != "" && (len(f) != 1 || f[0].Severity != tc.want):
			t.Errorf("%s: want one %s finding, got %+v", tc.imp, tc.want, f)
		}
	}
	// Trailing punctuation is not part of the path, and the same path twice is
	// reported once.
	f := CFG116.Check(&Target{Scope: finding.ScopeProject, InstructionFile: "CLAUDE.md", ExternalImports: []string{"~/x.md,", "~/x.md"}})
	if len(f) != 1 || !strings.Contains(f[0].Message, `"@~/x.md"`) {
		t.Errorf("want one finding for @~/x.md, got %+v", f)
	}
}
