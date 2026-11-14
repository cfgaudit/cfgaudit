// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io/fs"
	"maps"
	"path/filepath"
	"slices"
	"sort"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
	"github.com/cfgaudit/cfgaudit/internal/scanroot"
	"github.com/cfgaudit/cfgaudit/rules"
)

// antigravityRoots are the folders whose mcp_config.json and hooks.json
// Antigravity CLI reads (#1057): the workspace .agents/, and each workspace
// plugin under .agents/plugins/<name>/ (docs/plugins, docs/build-plugins),
// and each plugin folder inside the repository that .agents/plugins.json
// names (#1639).
func antigravityRoots(dir string) []string {
	roots := []string{filepath.Join(dir, ".agents")}
	entries, _ := scanroot.ReadDir(filepath.Join(dir, ".agents", "plugins"))
	for _, e := range entries {
		if e.IsDir() {
			roots = append(roots, filepath.Join(dir, ".agents", "plugins", e.Name()))
		}
	}
	for _, p := range antigravityManifest(dir, "plugins").Items {
		if !slices.Contains(roots, p) {
			roots = append(roots, p)
		}
	}
	return roots
}

// antigravityManifestFiles returns the skill, rule and agent files that
// .agents/skills.json, rules.json and agents.json add inside the repository
// (#1639).
func antigravityManifestFiles(dir string) []string {
	var out []string
	for _, kind := range []string{"skills", "rules", "agents"} {
		out = append(out, antigravityManifest(dir, kind).Items...)
	}
	return out
}

// antigravityManifestTargets reports the manifests that do not parse and
// returns a target per manifest read, with the entries in it that point
// outside the repository for CFG144 (#1639).
func antigravityManifestTargets(dir string) []*rules.Target {
	var targets []*rules.Target
	for _, kind := range antigravityManifestKinds {
		res := antigravityManifest(dir, kind)
		for _, path := range slices.Sorted(maps.Keys(res.Broken)) {
			skipUnreadable(path, res.Broken[path])
		}
		for _, path := range res.Read {
			t := &rules.Target{Scope: finding.ScopeProject, AntigravityManifestFile: path}
			for _, e := range res.Outside {
				if e.File == path {
					t.AntigravityOutside = append(t.AntigravityOutside, e)
				}
			}
			targets = append(targets, t)
		}
	}
	return targets
}

// antigravityTargets returns the MCP and hook targets of a workspace's
// Antigravity files. The servers ride the shared MCP rules and the hook
// commands the command-content rules, with SessionStart as the zero-click
// event CFG086 reports.
func antigravityTargets(dir string) []*rules.Target {
	targets := antigravityManifestTargets(dir)
	for i, root := range antigravityRoots(dir) {
		mcp := filepath.Join(root, "mcp_config.json")
		if servers, err := parser.ParseAntigravityMCP(mcp); err == nil {
			if len(servers) > 0 {
				targets = append(targets, &rules.Target{Scope: finding.ScopeProject, ProjectMCP: servers, ProjectMCPFile: mcp})
			}
		} else if !scanroot.IsAbsent(err) {
			skipUnreadable(mcp, err)
		}
		kind := "Antigravity"
		if i > 0 {
			kind = "Antigravity plugin " + filepath.Base(root)
		}
		hooks := filepath.Join(root, "hooks.json")
		if h, err := parser.ParseAntigravityHooks(hooks); err == nil {
			if len(h.Hooks) > 0 {
				targets = append(targets, &rules.Target{Scope: finding.ScopeProject, AgentHooks: h, AgentHooksFile: hooks, AgentHooksKind: kind})
			}
		} else if !scanroot.IsAbsent(err) {
			skipUnreadable(hooks, err)
		}
	}
	return targets
}

// antigravityInstructionFiles returns the Antigravity files whose text reaches
// the model beyond what the shared discovery reads (AGENTS.md, GEMINI.md,
// .agents/skills, .agents/agents): .agents/AGENTS.md, .agents/GEMINI.md and
// .agents/rules/*.md (docs/rules), the legacy .agent/rules/*.md and
// .agent/skills/**/SKILL.md, and in each workspace plugin its
// skills/**/SKILL.md, agents/*.md and agents/<name>/agent.md, and rules/*.md.
func antigravityInstructionFiles(dir string) []string {
	var out []string
	glob := func(pattern string) {
		matches, _ := scanroot.Glob(filepath.Join(dir, pattern))
		for _, m := range matches {
			if isRegularFile(m) {
				out = append(out, m)
			}
		}
	}
	skills := func(root string) {
		_ = scanroot.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && isSkillFile(d.Name()) {
				out = append(out, p)
			}
			return nil
		})
	}
	glob(filepath.Join(".agents", "AGENTS.md"))
	glob(filepath.Join(".agents", "GEMINI.md"))
	glob(filepath.Join(".agents", "rules", "*.md"))
	glob(filepath.Join(".agent", "rules", "*.md"))
	skills(filepath.Join(dir, ".agent", "skills"))
	for _, root := range antigravityRoots(dir)[1:] {
		rel, _ := filepath.Rel(dir, root)
		skills(filepath.Join(root, "skills"))
		glob(filepath.Join(rel, "agents", "*.md"))
		glob(filepath.Join(rel, "agents", "*", "agent.md"))
		glob(filepath.Join(rel, "rules", "*.md"))
	}
	sort.Strings(out)
	return out
}
