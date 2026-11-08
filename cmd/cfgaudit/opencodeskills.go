// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/parser"
	"github.com/cfgaudit/cfgaudit/internal/scanroot"
)

// openCodeSkillRoots are the project folders OpenCode 2 scans for skills: the
// skill and skills folders of .opencode, and, through its compatibility plugin,
// .claude/skills and .agents/skills (config/plugin/{skill,compatibility}.ts,
// v2.2.6).
var openCodeSkillRoots = []string{
	filepath.Join(".opencode", "skill"),
	filepath.Join(".opencode", "skills"),
	filepath.Join(".claude", "skills"),
	filepath.Join(".agents", "skills"),
}

// openCodeSkillScanDepth is MAX_DEPTH of SkillScan.scan.
const openCodeSkillScanDepth = 6

// openCodeIgnoredDirs is FSUtil.ignoredDirectories; hidden entries are skipped
// as well.
var openCodeIgnoredDirs = map[string]bool{"node_modules": true, ".git": true, ".venv": true, "venv": true, "__pycache__": true}

// openCodeSkillScan is SkillScan.scan (OpenCode 2.1+, #748): breadth first from
// root, a folder that holds SKILL.md is one skill and is not searched further,
// a loose *.md counts only directly in root, hidden entries and the ignored
// folders are skipped, and the walk stops six levels below root. A symlinked
// folder is not followed, so the scan stays inside the repository.
func openCodeSkillScan(root string) []string {
	type item struct {
		dir   string
		depth int
	}
	var out []string
	queue := []item{{root, 0}}
	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		entries, err := scanroot.ReadDir(it.dir)
		if err != nil {
			continue
		}
		var files, dirs []string
		skill := ""
		for _, e := range entries {
			name := e.Name()
			if strings.HasPrefix(name, ".") || openCodeIgnoredDirs[name] {
				continue
			}
			p := filepath.Join(it.dir, name)
			switch {
			case e.IsDir():
				dirs = append(dirs, p)
			case e.Type().IsRegular() || (e.Type()&fs.ModeSymlink != 0 && openCodeLinkedFile(p)):
				if name == "SKILL.md" {
					skill = p
				}
				files = append(files, p)
			}
		}
		if skill != "" {
			out = append(out, skill)
			continue
		}
		if it.depth == 0 {
			for _, f := range files {
				if strings.HasSuffix(f, ".md") {
					out = append(out, f)
				}
			}
		}
		if it.depth < openCodeSkillScanDepth {
			for _, d := range dirs {
				queue = append(queue, item{d, it.depth + 1})
			}
		}
	}
	sort.Strings(out)
	return out
}

// openCodeLinkedFile reports whether a symlink points at a regular file.
func openCodeLinkedFile(path string) bool {
	info, err := scanroot.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// openCodeSkillDir resolves one `skills` path entry and says whether it stays
// in the repository. OpenCode expands ~/ to the home directory, keeps an
// absolute path, and joins a relative one to the project directory; an
// http(s) URL is a remote source.
func openCodeSkillDir(dir, entry string) (string, bool) {
	low := strings.ToLower(entry)
	if strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://") || strings.HasPrefix(entry, "~") ||
		filepath.IsAbs(entry) || strings.HasPrefix(entry, "/") || strings.HasPrefix(entry, `\`) || (len(entry) >= 2 && entry[1] == ':') {
		return "", false
	}
	p := filepath.Join(dir, filepath.FromSlash(entry))
	rel, err := filepath.Rel(dir, p)
	if err != nil || !filepath.IsLocal(rel) {
		return "", false
	}
	return p, true
}

// openCodeSkillFiles returns the skill files OpenCode 2 loads from the project:
// the scan of each skill root and of each `skills` path inside the repository
// in a project config file.
func openCodeSkillFiles(dir string) []string {
	roots := make([]string, 0, len(openCodeSkillRoots))
	for _, r := range openCodeSkillRoots {
		roots = append(roots, filepath.Join(dir, r))
	}
	for _, rel := range openCodeConfigFiles {
		// A broken file is CFG109's, reported by openCodeTargets.
		cfg, err := parser.ParseOpenCodeConfig(filepath.Join(dir, rel))
		if err != nil {
			continue
		}
		for _, e := range cfg.SkillSources() {
			if p, inside := openCodeSkillDir(dir, e); inside {
				roots = append(roots, p)
			}
		}
	}
	var out []string
	for _, r := range roots {
		out = append(out, openCodeSkillScan(r)...)
	}
	sort.Strings(out)
	return out
}
