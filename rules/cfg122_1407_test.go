// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// #1407: the search and text tools agents start themselves, from
// CVE-2026-95660 (fd, stty) and beyond.
func TestToolBinaries1407(t *testing.T) {
	for _, base := range []string{"fd", "rg", "ripgrep", "stty", "find", "grep", "sed", "awk"} {
		for _, name := range []string{base + ".exe", strings.ToUpper(base) + ".CMD", base + ".bat", base + ".com"} {
			f := CFG123.Check(&Target{ProjectDir: "/r", RootFiles: []string{name}})
			if len(f) != 1 || f[0].Severity != finding.Error {
				t.Errorf("CFG123 %s: %+v", name, f)
			}
			f = CFG122.Check(&Target{ArchiveName: "r.zip", ArchiveEntries: []string{name}})
			if len(f) != 1 || f[0].Severity != finding.Error || f[0].File != "r.zip/"+name {
				t.Errorf("CFG122 %s: %+v", name, f)
			}
		}
	}
	for _, name := range []string{"fd.txt", "stty.md", "finder.exe", "rgx.exe"} {
		if f := CFG123.Check(&Target{ProjectDir: "/r", RootFiles: []string{name}}); len(f) != 0 {
			t.Errorf("CFG123 %s: %+v", name, f)
		}
	}
	if f := CFG122.Check(&Target{ArchiveName: "r.zip", ArchiveEntries: []string{"tools/fd.exe", "fd.txt"}}); len(f) != 0 {
		t.Errorf("CFG122 nested: %+v", f)
	}
}
