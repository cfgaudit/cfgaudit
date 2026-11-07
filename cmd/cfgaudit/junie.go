// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
	"github.com/cfgaudit/cfgaudit/internal/scanroot"
	"github.com/cfgaudit/cfgaudit/rules"
)

// junieDefaults are the default project folders of Junie (#1413): skills,
// slash commands and subagents, each also extended by a *-locations key.
var junieDefaults = map[string]string{
	"skill-locations":   filepath.Join(".junie", "skills"),
	"command-locations": filepath.Join(".junie", "commands"),
	"agent-locations":   filepath.Join(".junie", "agents"),
	"mcp-locations":     filepath.Join(".junie", "mcp"),
}

// junieConfigPath is the project config. Junie resolves its relative paths
// against the folder that holds it.
func junieConfigPath(dir string) string { return filepath.Join(dir, ".junie", "config.json") }

// junieFolders returns, for one *-locations key, the default folder and every
// configured folder inside the repository, deduplicated. A broken config is
// CFG109's, reported by junieTargets, so it is read silently here.
func junieFolders(dir, key string) []string {
	out := []string{}
	seen := map[string]bool{}
	addDir := func(p string) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	if d, ok := junieDefaults[key]; ok {
		addDir(filepath.Join(dir, d))
	}
	if c, err := parser.ParseJunieConfig(junieConfigPath(dir)); err == nil {
		for _, loc := range c.Locations[key] {
			for _, p := range junieCandidates(dir, loc) {
				addDir(p)
			}
		}
	}
	return out
}

// junieCandidates are the paths a location can mean inside the repository. The
// docs resolve it against .junie/, but configs in the wild also write it from
// the repository root (".junie/skills" in .junie/config.json), so both readings
// are read when they stay inside. Whether a location leaves the repository is
// decided by the documented reading alone.
func junieCandidates(dir, loc string) []string {
	p, inside := junieResolve(dir, loc)
	if !inside {
		return nil
	}
	out := []string{p}
	if q := filepath.Join(dir, filepath.FromSlash(loc)); q != p {
		if rel, err := filepath.Rel(dir, q); err == nil && filepath.IsLocal(rel) {
			out = append(out, q)
		}
	}
	return out
}

// junieResolve resolves a location against .junie/ and says whether it stays in
// the repository. A ~ path, an absolute path and one that climbs out do not.
func junieResolve(dir, loc string) (string, bool) {
	if strings.HasPrefix(loc, "~") || filepath.IsAbs(loc) || strings.HasPrefix(loc, "/") || strings.HasPrefix(loc, `\`) {
		return "", false
	}
	p := filepath.Join(dir, ".junie", filepath.FromSlash(loc))
	rel, err := filepath.Rel(dir, p)
	if err != nil || !filepath.IsLocal(rel) {
		return "", false
	}
	return p, true
}

// junieInstructionFiles are the guideline files, skills, commands and subagents
// Junie reads from a project, beside the root AGENTS.md read for every agent.
func junieInstructionFiles(dir string) []string {
	var out []string
	glob := func(pattern string) {
		m, _ := scanroot.Glob(pattern)
		out = append(out, m...)
	}
	for _, rel := range []string{"AGENTS.md", "playbook.md", "guidelines.md"} {
		glob(filepath.Join(dir, ".junie", rel))
	}
	glob(filepath.Join(dir, ".junie", "rules", "*.md"))
	glob(filepath.Join(dir, ".junie", "guidelines", "*.md"))
	if c, err := parser.ParseJunieConfig(junieConfigPath(dir)); err == nil {
		for _, loc := range c.Locations["guidelines-location"] {
			for _, p := range junieCandidates(dir, loc) {
				if p != filepath.Join(dir, "AGENTS.md") {
					glob(p)
				}
			}
		}
	}
	for _, d := range junieFolders(dir, "skill-locations") {
		glob(filepath.Join(d, "*", "SKILL.md"))
	}
	for _, key := range []string{"command-locations", "agent-locations"} {
		for _, d := range junieFolders(dir, key) {
			glob(filepath.Join(d, "*.md"))
		}
	}
	sort.Strings(out)
	return slices.Compact(out)
}

// junieMCPFiles are the mcp.json files of the default and configured folders.
func junieMCPFiles(dir string) []string {
	var out []string
	for _, d := range junieFolders(dir, "mcp-locations") {
		out = append(out, filepath.Join(d, "mcp.json"))
	}
	return out
}

// junieTargets returns the project config as a target, with the locations that
// leave the repository.
func junieTargets(dir string) []*rules.Target {
	path := junieConfigPath(dir)
	c, err := parser.ParseJunieConfig(path)
	if err != nil {
		if !scanroot.IsAbsent(err) {
			skipUnreadable(path, err)
		}
		return nil
	}
	var outside []rules.JunieLocation
	for _, key := range parser.JunieLocationKeys {
		for _, loc := range c.Locations[key] {
			if _, inside := junieResolve(dir, loc); !inside {
				outside = append(outside, rules.JunieLocation{Key: key, Value: loc})
			}
		}
	}
	if len(outside) == 0 && len(c.BYOK) == 0 && len(c.Proxies) == 0 {
		return nil
	}
	return []*rules.Target{{Scope: finding.ScopeProject, Junie: c, JunieFile: path, JunieOutside: outside}}
}
