// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"io/fs"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/cfgaudit/cfgaudit/internal/config"
	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/scanroot"
	"github.com/cfgaudit/cfgaudit/rules"
)

// pathList is a repeatable, comma-separated flag of path globs.
type pathList []string

func (p *pathList) String() string { return strings.Join(*p, ",") }

func (p *pathList) Set(v string) error {
	for _, raw := range strings.Split(v, ",") {
		if s := strings.TrimSpace(raw); s != "" {
			*p = append(*p, s)
		}
	}
	return nil
}

// contentPathTargets returns one target per file under dir that a glob in
// globs matches (#795), for the rules in rules.ContentPathRules. A file that
// is already an instruction target is left to that target, and the .git
// directory is not walked.
func contentPathTargets(dir string, globs []string, targets []*rules.Target) ([]*rules.Target, error) {
	if len(globs) == 0 {
		return nil, nil
	}
	known := map[string]bool{}
	for _, t := range targets {
		if t.InstructionFile == "" {
			continue
		}
		if abs, err := filepath.Abs(t.InstructionFile); err == nil {
			known[abs] = true
		}
	}
	var out []*rules.Target
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error { // #nosec G703 -- dir is the directory the user asked to scan; reads go through scanroot
		if err != nil {
			return nil // an unreadable directory is skipped, not fatal
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil || !matchesAny(globs, filepath.ToSlash(rel)) {
			return nil
		}
		if abs, err := filepath.Abs(path); err != nil || known[abs] {
			return nil
		}
		data, err := scanroot.ReadFile(path)
		if err != nil || !utf8.Valid(data) || bytes.Contains(data, []byte{0}) {
			return nil
		}
		out = append(out, &rules.Target{
			Scope:              finding.ScopeProject,
			InstructionFile:    path,
			InstructionContent: string(data),
			ContentPath:        true,
		})
		return nil
	})
	return out, err
}

func matchesAny(globs []string, rel string) bool {
	for _, g := range globs {
		if config.MatchGlob(g, rel) {
			return true
		}
	}
	return false
}
