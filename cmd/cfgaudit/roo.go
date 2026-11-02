// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/scanroot"
)

// rooJunkSuffixes are the files Roo Code leaves out of a rules directory:
// "Only cache/temp files are excluded (.DS_Store, *.bak, *.cache, *.log,
// *.tmp, Thumbs.db)" (custom-instructions docs).
var rooJunkSuffixes = []string{".bak", ".cache", ".log", ".tmp"}

// rooInstructionFiles returns the Roo Code instruction files of a project
// (#989), sorted. Roo Code "reads files recursively (including
// subdirectories)" from .roo/rules/ and the mode directories
// .roo/rules-{modeSlug}/, of any extension, and falls back to .roorules and
// .roorules-{modeSlug} at the root. .roomodes carries each custom mode's
// roleDefinition, whenToUse and customInstructions, so the whole file is read
// as instruction text: its lines keep their numbers. .clinerules, the legacy
// fallback, is read for Cline already.
func rooInstructionFiles(base string) []string {
	var out []string
	add := func(path string) {
		name := filepath.Base(path)
		if name == ".DS_Store" || name == "Thumbs.db" {
			return
		}
		for _, s := range rooJunkSuffixes {
			if strings.HasSuffix(name, s) {
				return
			}
		}
		out = append(out, path)
	}
	dirs := []string{filepath.Join(base, ".roo", "rules")}
	if modes, err := scanroot.Glob(filepath.Join(base, ".roo", "rules-*")); err == nil {
		dirs = append(dirs, modes...)
	}
	for _, d := range dirs {
		_ = scanroot.WalkDir(d, func(path string, e fs.DirEntry, err error) error {
			if err == nil && !e.IsDir() {
				add(path)
			}
			return nil
		})
	}
	for _, pat := range []string{".roorules", ".roorules-*", ".roomodes"} {
		matches, _ := scanroot.Glob(filepath.Join(base, pat))
		for _, m := range matches {
			if fi, err := scanroot.Stat(m); err == nil && fi.Mode().IsRegular() {
				add(m)
			}
		}
	}
	sort.Strings(out)
	return out
}
