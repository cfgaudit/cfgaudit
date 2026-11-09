// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"io/fs"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/gitindex"
	"github.com/cfgaudit/cfgaudit/internal/parser"
	"github.com/cfgaudit/cfgaudit/internal/scanroot"
	"github.com/cfgaudit/cfgaudit/rules"
)

// Gemini CLI extensions (#1556), read from packages/cli/src/config/
// extension-manager.ts at v0.67.0. An extension is a folder with a
// gemini-extension.json. Gemini loads every folder of
// <home>/.gemini/extensions, and an extension is enabled by default.

// geminiExtensionRoot is one extension folder and whether Gemini loads it as
// installed: from a repository-relative GEMINI_CLI_HOME (#749), as opposed to
// an extension the repository publishes for others to install.
type geminiExtensionRoot struct {
	dir       string
	installed bool
}

// geminiExtensionRoots returns the extension folders of a project, sorted:
//
//   - every folder of <dir>/<GEMINI_CLI_HOME>/.gemini/extensions when
//     .gemini/.env sets GEMINI_CLI_HOME to a folder in the repository, which
//     Gemini then treats as the user's home (homedir() in core/utils/paths.ts);
//   - every other folder holding a gemini-extension.json, outside
//     node_modules, vendor and third_party: an extension the repository
//     publishes, which runs on the machine of whoever installs it.
func geminiExtensionRoots(dir string) []geminiExtensionRoot {
	seen := map[string]bool{}
	var out []geminiExtensionRoot
	if env, err := parser.ParseDotEnv(filepath.Join(dir, ".gemini", ".env")); err == nil {
		if home := strings.TrimSpace(env["GEMINI_CLI_HOME"]); home != "" && !filepath.IsAbs(home) && !strings.HasPrefix(home, "~") && !strings.HasPrefix(home, "$") {
			base := filepath.Join(dir, filepath.FromSlash(home), ".gemini", "extensions")
			if rel, err := filepath.Rel(dir, base); err == nil && filepath.IsLocal(rel) {
				entries, _ := scanroot.ReadDir(base)
				for _, e := range entries {
					if e.IsDir() {
						p := filepath.Join(base, e.Name())
						seen[p] = true
						out = append(out, geminiExtensionRoot{p, true})
					}
				}
			}
		}
	}
	for _, rel := range geminiManifestFiles(dir) {
		p := filepath.Join(dir, filepath.FromSlash(path.Dir(rel)))
		if !seen[p] {
			seen[p] = true
			out = append(out, geminiExtensionRoot{p, false})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].dir < out[j].dir })
	return out
}

// geminiManifestFiles returns the gemini-extension.json files of a project,
// slash-separated and relative to dir: the tracked ones from the git index
// when there is one, otherwise from a walk.
func geminiManifestFiles(dir string) []string {
	var out []string
	keep := func(rel string) {
		if path.Base(rel) != "gemini-extension.json" {
			return
		}
		for _, seg := range strings.Split(rel, "/") {
			if nestedAgentsSkipDirs[seg] {
				return
			}
		}
		out = append(out, rel)
	}
	if tracked, ok := gitindex.Tracked(dir); ok {
		for p := range tracked {
			keep(p)
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
		if rel, err := filepath.Rel(root, p); err == nil {
			keep(filepath.ToSlash(rel))
		}
		return nil
	})
	sort.Strings(out)
	return out
}

// geminiExtensionManifest is the part of gemini-extension.json read here
// besides its mcpServers, which the Gemini settings parser reads.
type geminiExtensionManifest struct {
	ContextFileName json.RawMessage `json:"contextFileName"`
}

// contextFiles returns the context file names of a manifest: the string or
// list contextFileName, or GEMINI.md when it is absent (getContextFileNames).
func (m geminiExtensionManifest) contextFiles() []string {
	var one string
	if json.Unmarshal(m.ContextFileName, &one) == nil && strings.TrimSpace(one) != "" {
		return []string{one}
	}
	var list []string
	if json.Unmarshal(m.ContextFileName, &list) == nil && len(list) > 0 {
		return list
	}
	return []string{"GEMINI.md"}
}

// geminiExtensionTargets returns, for each extension folder, the targets of
// its manifest (the MCP servers ride the shared MCP rules) and of
// hooks/hooks.json (the Gemini hook rules, loaded when hooksConfig.enabled),
// and for an installed extension a link install whose source leaves the
// repository.
func geminiExtensionTargets(dir string) []*rules.Target {
	var targets []*rules.Target
	for _, root := range geminiExtensionRoots(dir) {
		manifest := filepath.Join(root.dir, "gemini-extension.json")
		if servers, err := parser.ParseGeminiExtensionMCP(manifest); err == nil {
			if len(servers) > 0 {
				targets = append(targets, &rules.Target{Scope: finding.ScopeProject, ProjectMCP: servers, ProjectMCPFile: manifest})
			}
		} else if !scanroot.IsAbsent(err) {
			skipUnreadable(manifest, err)
		}
		hooks := filepath.Join(root.dir, "hooks", "hooks.json")
		if gs, err := parseGeminiOptional(hooks, nil); err == nil && gs != nil && len(gs.Hooks) > 0 {
			targets = append(targets, &rules.Target{Scope: finding.ScopeProject, Gemini: &parser.GeminiSettings{Hooks: gs.Hooks}, GeminiFile: hooks, GeminiExtensionPublished: !root.installed})
		}
		if !root.installed {
			continue
		}
		meta := filepath.Join(root.dir, ".gemini-extension-install.json")
		data, err := scanroot.ReadFile(meta)
		if err != nil {
			continue
		}
		var install struct {
			Type, Source string
		}
		if json.Unmarshal(data, &install) == nil && install.Type == "link" && rules.OpenCodeOutside(install.Source) != "" {
			targets = append(targets, &rules.Target{Scope: finding.ScopeProject, GeminiExtensionLink: install.Source, GeminiExtensionLinkFile: meta})
		}
	}
	return targets
}

// geminiExtensionFiles returns the instruction files and the custom command
// files of each extension folder: the context files the manifest names that
// stay in the folder, skills/**/SKILL.md, agents/*.md, and commands/**/*.toml
// (FileCommandLoader reads an active extension's commands folder).
func geminiExtensionFiles(dir string) (instructions, commands []string) {
	for _, root := range geminiExtensionRoots(dir) {
		var m geminiExtensionManifest
		if data, err := scanroot.ReadFile(filepath.Join(root.dir, "gemini-extension.json")); err == nil {
			_ = json.Unmarshal(data, &m)
		}
		for _, name := range m.contextFiles() {
			p := filepath.Join(root.dir, filepath.FromSlash(name))
			if rel, err := filepath.Rel(root.dir, p); err == nil && filepath.IsLocal(rel) && isRegularFile(p) {
				instructions = append(instructions, p)
			}
		}
		_ = scanroot.WalkDir(filepath.Join(root.dir, "skills"), func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && isSkillFile(d.Name()) {
				instructions = append(instructions, p)
			}
			return nil
		})
		agents, _ := scanroot.Glob(filepath.Join(root.dir, "agents", "*.md"))
		instructions = append(instructions, agents...)
		_ = scanroot.WalkDir(filepath.Join(root.dir, "commands"), func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && filepath.Ext(p) == ".toml" {
				commands = append(commands, p)
			}
			return nil
		})
	}
	sort.Strings(instructions)
	sort.Strings(commands)
	return instructions, commands
}
