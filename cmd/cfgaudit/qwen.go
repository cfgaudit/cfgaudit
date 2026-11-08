// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/parser"
	"github.com/cfgaudit/cfgaudit/internal/scanroot"
)

// qwenSkillDir resolves one skills.directories entry of the project settings
// and says whether it stays in the repository (#973). Qwen expands ~ and
// %userprofile% to the home directory and resolves a relative entry against
// the working directory, which cfgaudit takes to be the repository root. A home
// path, an absolute path and one that climbs out do not stay.
func qwenSkillDir(dir, entry string) (string, bool) {
	low := strings.ToLower(entry)
	if strings.HasPrefix(entry, "~") || strings.HasPrefix(low, "%userprofile%") || filepath.IsAbs(entry) ||
		strings.HasPrefix(entry, "/") || strings.HasPrefix(entry, `\`) || (len(entry) >= 2 && entry[1] == ':') {
		return "", false
	}
	p := filepath.Join(dir, filepath.FromSlash(strings.ReplaceAll(entry, `\`, "/")))
	rel, err := filepath.Rel(dir, p)
	if err != nil || !filepath.IsLocal(rel) {
		return "", false
	}
	return p, true
}

// qwenSettingsSkillDirs returns the skills.directories entries of the project
// .qwen/settings.json. A broken file is CFG109's, reported by qwenTargets, so it
// is read silently here.
func qwenSettingsSkillDirs(dir string) []string {
	qs, err := parser.ParseQwenSettings(filepath.Join(dir, ".qwen", "settings.json"))
	if err != nil {
		return nil
	}
	return qs.SkillDirectories()
}

// qwenOutsideSkillDirs returns the entries that leave the repository.
func qwenOutsideSkillDirs(dir string, entries []string) []string {
	var out []string
	for _, e := range entries {
		if _, inside := qwenSkillDir(dir, e); !inside {
			out = append(out, e)
		}
	}
	return out
}

// qwenSkillFiles returns <directory>/<skill-name>/SKILL.md for each
// skills.directories entry inside the repository. Qwen reads one level deep: a
// skill nested further is not found.
func qwenSkillFiles(dir string) []string {
	var out []string
	for _, e := range qwenSettingsSkillDirs(dir) {
		if p, inside := qwenSkillDir(dir, e); inside {
			m, _ := scanroot.Glob(filepath.Join(p, "*", "SKILL.md"))
			out = append(out, m...)
		}
	}
	sort.Strings(out)
	return out
}
