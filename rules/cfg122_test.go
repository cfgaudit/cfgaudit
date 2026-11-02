// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG122_ArchiveOnly1002(t *testing.T) {
	tg := &Target{ArchiveName: "r.zip", ArchiveEntries: []string{".git", ".git/config", "sub/.git", "git.exe", "sub/node.cmd", "README.md"}, ArchiveLinks: []string{"a", "b", "c", "d", "e", "f"}}
	got := map[string]finding.Severity{}
	for _, f := range CFG122.Check(tg) {
		got[f.File] = f.Severity
	}
	want := map[string]finding.Severity{"r.zip/.git": finding.Error, "r.zip/sub/.git": finding.Error, "r.zip/git.exe": finding.Error, "r.zip": finding.Warn}
	if len(got) != len(want) {
		t.Errorf("got %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %s, want %s", k, got[k], v)
		}
	}
	if f := CFG122.Check(&Target{ArchiveEntries: []string{".git"}}); f != nil {
		t.Errorf("not an archive target: %+v", f)
	}
}
