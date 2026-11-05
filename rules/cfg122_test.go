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
		{Name: "outside", Target: "../shared/readme.md"},
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

// A link to a sensitive name that stays inside the archive leads to another
// entry. It stays a warning, like any link that was not extracted.
func TestCFG122_LinkInsideTheArchiveIsNotSensitive1435(t *testing.T) {
	tg := &Target{ArchiveName: "r.tgz", ArchiveLinks: []ArchiveLink{
		{Name: "repo/.cursor/rules", Target: "../.claude/rules"},
		{Name: "repo/AGENTS.md", Target: ".claude/CLAUDE.md"},
		{Name: "repo/copy", Target: "repo/.claude/settings.json", Hard: true},
	}}
	got := CFG122.Check(tg)
	if len(got) != 1 || got[0].Severity != finding.Warn {
		t.Fatalf("got %+v", got)
	}
}

func TestCFG122_LinkLeavingTheArchive1435(t *testing.T) {
	for _, link := range []ArchiveLink{
		{Name: "a", Target: "/home/u/.ssh/id_rsa"},
		{Name: "a", Target: "~/.ssh/id_rsa"},
		{Name: "a", Target: "$HOME/.ssh/id_rsa"},
		{Name: "a", Target: `%USERPROFILE%\.ssh\id_rsa`},
		{Name: "a", Target: `C:\Users\u\.ssh\id_rsa`},
		{Name: "a/b", Target: "../../.ssh/id_rsa"},
		{Name: "a/b", Target: `..\..\.ssh\id_rsa`},
		{Name: "a/b", Target: "../.ssh/x/../../..", Hard: false},
		{Name: "x", Target: "../.ssh/id_rsa", Hard: true},
	} {
		if !archiveLinkLeaves(link) {
			t.Errorf("%+v: expected to leave", link)
		}
	}
	if archiveLinkLeaves(ArchiveLink{Name: "a/b", Target: "../.ssh/id_rsa"}) {
		t.Error("stays inside: reported as leaving")
	}
}
