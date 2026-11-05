// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG122_ArchiveOnly1002(t *testing.T) {
	tg := &Target{ArchiveName: "r.zip", ArchiveEntries: []string{".git", ".git/config", "sub/.git", "git.exe", "sub/node.cmd", "README.md"}, ArchiveLinks: []ArchiveLink{{Name: "a"}, {Name: "b"}, {Name: "c"}, {Name: "d"}, {Name: "e"}, {Name: "f"}}}
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

func TestCFG122_ClassifiesArchiveLinkTargets(t *testing.T) {
	tg := &Target{ArchiveName: "release.tar", ArchiveLinks: []ArchiveLink{
		{Name: "keys", Target: "../../.ssh/id_ed25519"},
		{Name: "npm", Target: `C:\\Users\\u\\.npmrc`},
		{Name: "hook", Target: "../repo/.git/hooks/pre-commit"},
		{Name: "inside", Target: "../shared/readme.md"},
	}}
	got := CFG122.Check(tg)
	if len(got) != 4 {
		t.Fatalf("got %+v", got)
	}
	for _, f := range got[:3] {
		if f.Severity != finding.Error {
			t.Errorf("sensitive link: got %+v", f)
		}
	}
	if got[3].Severity != finding.Warn || got[3].File != "release.tar" {
		t.Errorf("ordinary links: got %+v", got[3])
	}
	for _, f := range got {
		if f.File == "release.tar/npm" && strings.Contains(f.Message, `\\`) {
			t.Errorf("mixed separators not normalised: %q", f.Message)
		}
	}
}
