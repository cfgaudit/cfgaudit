// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/scanroot"
	"github.com/cfgaudit/cfgaudit/rules"
)

// maxSkillHelper caps the size of a helper file that is read (#987).
const maxSkillHelper = 1 << 20

// skillScriptExts are the script extensions read beside a SKILL.md: shell
// scripts, whose lines the command rules read.
var skillScriptExts = map[string]bool{".sh": true, ".bash": true, ".zsh": true}

// skillCodeExts are the other scripts a skill ships. CFG119 reads them for its
// markers, and the line rules do not, whose patterns are shell syntax (#1409).
var skillCodeExts = map[string]bool{".py": true, ".js": true, ".mjs": true, ".cjs": true, ".ts": true}

// skillHelperTargets reads the files a skill ships next to its SKILL.md
// (#987). Only SKILL.md got the instruction rules, so a skill could keep a
// harmless SKILL.md and move the payload into a file it tells the agent to
// read or run; a ransomware-dropping skill was built that way.
//
// Each Markdown file under a skill directory becomes a target for the rules
// in rules.SkillHelperRules. Each shell script is attached to the skill's
// target as a launched script, so the rules that read the scripts auto-run
// commands start (#1217) read its lines too; rules.Run reports those
// findings at most at warn. A directory with a SKILL.md of its own is
// another skill and is left to it, files that are already a target or a
// launched script are skipped, and so are files over 1 MiB, binary files and
// node_modules.
func skillHelperTargets(dir string, targets []*rules.Target) []*rules.Target {
	root := absPath(dir)
	known := map[string]bool{}
	for _, t := range targets {
		if t.InstructionFile != "" {
			known[absPath(t.InstructionFile)] = true
		}
		for _, s := range t.LaunchedScripts {
			known[absPath(s.File)] = true
		}
	}
	var out []*rules.Target
	for _, t := range targets {
		if t.InstructionFile == "" || filepath.Base(t.InstructionFile) != "SKILL.md" || t.SkillHelper != "" {
			continue
		}
		skillDir := filepath.Dir(t.InstructionFile)
		skill := relSlash(root, absPath(t.InstructionFile))
		var scripts []rules.LaunchedScript
		_ = scanroot.WalkDir(skillDir, func(path string, d fs.DirEntry, err error) error { // skillDir is a discovered skill under the scanned directory; reads go through scanroot
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if path == skillDir {
					return nil
				}
				if d.Name() == ".git" || d.Name() == "node_modules" {
					return filepath.SkipDir
				}
				if _, err := scanroot.Stat(filepath.Join(path, "SKILL.md")); err == nil {
					return filepath.SkipDir
				}
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			isMD := ext == ".md" && d.Name() != "SKILL.md"
			if (!isMD && !skillScriptExts[ext] && !skillCodeExts[ext]) || known[absPath(path)] {
				return nil
			}
			data, err := scanroot.ReadFile(path)
			if err != nil || len(data) > maxSkillHelper || !isTextFile(data) {
				return nil
			}
			known[absPath(path)] = true
			rel := filepath.ToSlash(strings.TrimPrefix(path, skillDir+string(filepath.Separator)))
			if isMD {
				out = append(out, &rules.Target{
					Scope:              t.Scope,
					ProjectDir:         t.ProjectDir,
					InstructionFile:    path,
					InstructionContent: string(data),
					SkillHelper:        skill,
					// #1611: a page the skill does not tell the agent to follow
					// is a reference page, reported at info.
					SkillHelperFollowed: rules.SkillTellsToFollow(t.InstructionContent, rel),
				})
				return nil
			}
			scripts = append(scripts, rules.LaunchedScript{
				Label:   "script " + rel + ", shipped with the skill " + skill + ",",
				File:    path,
				Content: string(data),
				Skill:   skill,
				Size:    int64(len(data)),
			})
			return nil
		})
		sort.Slice(scripts, func(i, j int) bool { return scripts[i].File < scripts[j].File })
		t.LaunchedScripts = append(t.LaunchedScripts, scripts...)
	}
	return out
}
