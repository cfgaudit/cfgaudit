// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/scanroot"
	"github.com/cfgaudit/cfgaudit/rules"
)

// gitWalkSkip are directories the nested-repository walk does not enter:
// the repository's own .git and the usual dependency and build trees.
var gitWalkSkip = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "target": true, "dist": true,
	"build": true, ".venv": true, "venv": true, "__pycache__": true, ".tox": true,
}

// maxGitWalkDepth bounds the walk for nested repositories.
const maxGitWalkDepth = 8

// gitTargets returns a target with the .gitmodules of dir and the committed
// directories that look like a bare git repository (#994): HEAD and config
// files next to objects/ and refs/ directories. An agent that runs git
// inside such a directory, or lets git discover it, runs what its config
// names. Nothing is executed here.
func gitTargets(dir string) []*rules.Target {
	t := &rules.Target{Scope: finding.ScopeProject}
	path := filepath.Join(dir, ".gitmodules")
	if data, err := scanroot.ReadFile(path); err == nil && isTextFile(data) {
		t.GitModules, t.GitModulesFile = string(data), path
	}
	root := filepath.Clean(dir)
	_ = scanroot.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			rel, _ := filepath.Rel(root, p)
			if p != root && (gitWalkSkip[d.Name()] || strings.Count(rel, string(filepath.Separator)) >= maxGitWalkDepth) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != "HEAD" {
			return nil
		}
		repo := filepath.Dir(p)
		for _, sub := range []string{"objects", "refs"} {
			if fi, err := scanroot.Stat(filepath.Join(repo, sub)); err != nil || !fi.IsDir() {
				return nil
			}
		}
		cfg := filepath.Join(repo, "config")
		data, err := scanroot.ReadFile(cfg)
		if err != nil || !isTextFile(data) {
			return nil
		}
		t.NestedRepos = append(t.NestedRepos, rules.NestedRepo{Dir: repo, ConfigFile: cfg, Config: string(data)})
		return nil
	})
	if t.GitModulesFile == "" && len(t.NestedRepos) == 0 {
		return nil
	}
	return []*rules.Target{t}
}
