// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
	"github.com/cfgaudit/cfgaudit/internal/scanroot"
	"github.com/cfgaudit/cfgaudit/rules"
)

// gooseRecipeDirs are the project recipe libraries of goose (#1414),
// crates/goose/src/recipe/local_recipes.rs local_recipe_dirs. A scan of one does
// not descend.
var gooseRecipeDirs = []string{filepath.Join(".goose", "recipes"), filepath.Join(".agents", "recipes")}

func isGooseRecipeName(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".yaml", ".json":
		return true
	}
	return false
}

// gooseTargets returns the recipes and project plugin hooks of a repository.
func gooseTargets(dir string) []*rules.Target {
	var targets []*rules.Target
	seen := map[string]bool{}
	var add func(path string, needShape bool)
	add = func(path string, needShape bool) {
		if seen[path] {
			return
		}
		seen[path] = true
		r, err := parser.ParseGooseRecipe(path)
		if err != nil {
			// Any YAML file at the root lands here, recipe or not.
			if !needShape && !scanroot.IsAbsent(err) {
				skipUnreadable(path, err)
			}
			return
		}
		if needShape && !r.IsRecipe {
			return
		}
		if len(r.Servers) > 0 || len(r.Commands) > 0 {
			t := &rules.Target{Scope: finding.ScopeProject, GooseRecipeCommands: r.Commands, GooseRecipeFile: path}
			if len(r.Servers) > 0 {
				t.ProjectMCP, t.ProjectMCPFile = r.Servers, path
			}
			targets = append(targets, t)
		}
		for _, sub := range r.SubRecipes {
			p := filepath.Join(filepath.Dir(path), filepath.FromSlash(sub))
			rel, err := filepath.Rel(dir, p)
			if err == nil && filepath.IsLocal(rel) && isGooseRecipeName(p) {
				add(p, false)
			}
		}
	}
	for _, rel := range gooseRecipeDirs {
		entries, err := scanroot.ReadDir(filepath.Join(dir, rel))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() && isGooseRecipeName(e.Name()) {
				add(filepath.Join(dir, rel, e.Name()), false)
			}
		}
	}
	// goose also finds a recipe by name in the current directory.
	entries, err := scanroot.ReadDir(dir)
	if err == nil {
		for _, e := range entries {
			if !e.IsDir() && isGooseRecipeName(e.Name()) {
				add(filepath.Join(dir, e.Name()), true)
			}
		}
	}

	// crates/goose/src/hooks/mod.rs: <plugin-root>/hooks/hooks.json of every
	// directory under .agents/plugins. No manifest is needed, and scanroot keeps
	// a linked plugin outside the repository from being read.
	plugins, _ := scanroot.ReadDir(filepath.Join(dir, ".agents", "plugins"))
	for _, e := range plugins {
		hp := filepath.Join(dir, ".agents", "plugins", e.Name(), "hooks", "hooks.json")
		h, err := parser.ParseGrokHooks(hp)
		if err != nil {
			if !scanroot.IsAbsent(err) {
				skipUnreadable(hp, err)
			}
			continue
		}
		if len(h.Hooks) > 0 {
			targets = append(targets, &rules.Target{Scope: finding.ScopeProject, GooseHooks: h, GooseHooksFile: hp})
		}
	}
	return targets
}

// goosehintsFiles returns the nested .goosehints files; goose reads them as it
// reaches their directory (crates/goose/src/hints/load_hints.rs). The root file
// is in agentInstructionFiles.
func goosehintsFiles(dir string) []string {
	var out []string
	root := filepath.Clean(dir)
	_ = scanroot.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable branch holds no file to report
		}
		rel, _ := filepath.Rel(root, p)
		if d.IsDir() {
			if p != root && (gitWalkSkip[d.Name()] || strings.Count(rel, string(filepath.Separator)) >= maxGitWalkDepth) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == ".goosehints" && filepath.Dir(p) != root {
			out = append(out, p)
		}
		return nil
	})
	return out
}
