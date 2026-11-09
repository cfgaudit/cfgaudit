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

// nestedAgentsSkipDirs are folders whose instruction files are a
// dependency's, not the project's.
var nestedAgentsSkipDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true, "third_party": true}

// nestedInstructionNames are the instruction files an agent reads from a
// folder below the root (#975):
//
//   - AGENTS.md: Cursor applies it when its agent edits a file in that folder
//     or below: "When the agent edits or creates a file in a subdirectory, it
//     now sees that directory's AGENTS.md [...], even if it never read a file
//     there first" (release notes, v2026.10.22).
//   - CLAUDE.md: Claude Code 2.1.319 describes "nested-directory CLAUDE.md
//     files (loaded when working under that directory)" next to the root file
//     and .claude/CLAUDE.md, "always loaded".
var nestedInstructionNames = map[string]bool{"AGENTS.md": true, "CLAUDE.md": true}

// nestedRuleDirs are the rule folders an agent reads from a folder below the
// root, with the file filter of the root folder (filteredInstructionDirs):
//
//   - .cursor/rules: Cursor's rules documentation places .cursor/rules
//     folders throughout a project, and nested rules attach when files in
//     their folder are in use; since v2026.10.22 nested always-apply rules
//     also apply when the agent edits a file there.
//   - .devin/rules and .windsurf/rules: Devin "also reads these directories
//     from any subdirectory of the workspace".
var nestedRuleDirs = []struct {
	dir   string
	match func(name string) bool
}{
	{".cursor/rules", func(name string) bool { return strings.HasSuffix(name, ".mdc") }},
	{".devin/rules", isMarkdown},
	{".windsurf/rules", isMarkdown},
}

// nestedFile is an instruction file below the root and the folder, relative
// to the scanned directory, whose work it applies to.
type nestedFile struct{ rel, dir string }

// nestedAgentsFiles returns the nestedInstructionNames files and the files of
// nestedRuleDirs below the root of dir, as slash-separated paths relative to
// dir. The tracked files of the git index are used when there is one, as for
// committed bytecode, otherwise the tree is walked. Files inside
// node_modules, vendor and third_party folders are left out.
func nestedAgentsFiles(dir string) []nestedFile {
	var out []nestedFile
	add := func(rel string) {
		for _, seg := range strings.Split(path.Dir(rel), "/") {
			if nestedAgentsSkipDirs[seg] {
				return
			}
		}
		if nestedInstructionNames[path.Base(rel)] && strings.Contains(rel, "/") {
			out = append(out, nestedFile{rel, path.Dir(rel)})
			return
		}
		for _, rd := range nestedRuleDirs {
			i := strings.Index(rel, "/"+rd.dir+"/")
			if i > 0 && rd.match(path.Base(rel)) {
				out = append(out, nestedFile{rel, rel[:i]})
				return
			}
		}
	}
	if tracked, ok := gitindex.Tracked(dir); ok {
		for p := range tracked {
			add(p)
		}
	} else {
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
			if rel, err := filepath.Rel(root, p); err == nil {
				add(filepath.ToSlash(rel))
			}
			return nil
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].rel < out[j].rel })
	return out
}
