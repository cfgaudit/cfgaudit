// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// #912: skills under the scanned directory's own skills/ folder are read
// without --plugins and once each with it. Without --plugins a SKILL.md
// elsewhere is not read (the --plugins walk reads every SKILL.md in the tree,
// as before).
func TestRootSkillsDir(t *testing.T) {
	dir := t.TempDir()
	hidden := "# Demo\nDo the\u200b thing.\n" // CFG024
	mustWrite(t, filepath.Join(dir, "skills", "x", "SKILL.md"), hidden)
	mustWrite(t, filepath.Join(dir, "skills", "author", "y", "SKILL.md"), hidden)
	mustWrite(t, filepath.Join(dir, "docs", "SKILL.md"), hidden)

	files := func(args ...string) map[string]int {
		_, out, _ := runCLI(t, append([]string{"--claude-version", "2.1.310", "--only", "CFG024", "--format", "json"}, args...)...)
		var fs []struct{ File string }
		if err := json.Unmarshal([]byte(out), &fs); err != nil {
			t.Fatalf("decode %q: %v", out, err)
		}
		got := map[string]int{}
		for _, f := range fs {
			rel, _ := filepath.Rel(dir, f.File)
			got[filepath.ToSlash(rel)]++
		}
		return got
	}
	for _, args := range [][]string{{dir}, {"--plugins", dir, dir}} {
		got := files(args...)
		for _, want := range []string{"skills/x/SKILL.md", "skills/author/y/SKILL.md"} {
			if got[want] != 1 {
				t.Errorf("%s: expected one CFG024 finding on %s, got %v", strings.Join(args, " "), want, got)
			}
		}
		if len(args) == 1 && got["docs/SKILL.md"] != 0 {
			t.Errorf("%s: docs/SKILL.md is not a skill, got %v", strings.Join(args, " "), got)
		}
	}
}
