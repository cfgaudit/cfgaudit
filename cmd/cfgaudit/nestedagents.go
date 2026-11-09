// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io/fs"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/gitindex"
	"github.com/cfgaudit/cfgaudit/internal/scanroot"
)

// nestedAgentsSkipDirs are folders whose AGENTS.md is a dependency's, not the
// project's.
var nestedAgentsSkipDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true, "third_party": true}

// nestedAgentsFiles returns the AGENTS.md files below the root of dir, as
// slash-separated paths relative to dir (#975). Cursor applies such a file
// when its agent edits a file in that folder or below: "When the agent edits
// or creates a file in a subdirectory, it now sees that directory's AGENTS.md
// [...], even if it never read a file there first" (release notes,
// v2026.10.22). The tracked files of the git index are used when there is
// one, as for committed bytecode, otherwise the tree is walked. Files inside
// node_modules, vendor and third_party folders are left out.
func nestedAgentsFiles(dir string) []string {
	var out []string
	keep := func(rel string) bool {
		if path.Base(rel) != "AGENTS.md" || !strings.Contains(rel, "/") {
			return false
		}
		for _, seg := range strings.Split(path.Dir(rel), "/") {
			if nestedAgentsSkipDirs[seg] {
				return false
			}
		}
		return true
	}
	if tracked, ok := gitindex.Tracked(dir); ok {
		for p := range tracked {
			if keep(p) {
				out = append(out, p)
			}
		}
		sort.Strings(out)
		return out
	}
	root := filepath.Clean(dir)
	_ = scanroot.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != root && nestedAgentsSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if rel, err := filepath.Rel(root, p); err == nil && keep(filepath.ToSlash(rel)) {
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	sort.Strings(out)
	return out
}
