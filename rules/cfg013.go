// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"errors"
	"github.com/cfgaudit/cfgaudit/internal/scanroot"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/gitindex"
)

type cfg013 struct{}

var CFG013 = &cfg013{}

func init() { All = append(All, CFG013) }

func (r *cfg013) ID() string { return "CFG013" }

// sensitiveLocalFiles are project-relative paths that Claude Code generates
// to hold developer-local state. They must not be committed to the repo.
var sensitiveLocalFiles = []string{
	".claude/settings.local.json",
	"CLAUDE.local.md",
}

func (r *cfg013) Check(t *Target) []finding.Finding {
	if t == nil || t.ProjectDir == "" {
		return nil
	}
	// Only fire from the canonical project target so we don't double-emit when
	// settings.json and settings.local.json both exist.
	if t.Scope != finding.ScopeProject {
		return nil
	}

	rules, gitignoreExists := loadGitignoreRules(filepath.Join(t.ProjectDir, ".gitignore"))
	// With a .git, the index says whether the file is committed. .gitignore
	// does not untrack a committed file, so that case is reported whether or
	// not .gitignore covers it. Without one (an archive, a checkout without
	// history) only the .gitignore check is possible (#1206).
	tracked, haveIndex := gitindex.Tracked(t.ProjectDir)

	var findings []finding.Finding
	for _, rel := range sensitiveLocalFiles {
		if haveIndex && tracked[rel] {
			covered := gitignoreExists && isGitignored(rules, rel)
			findings = append(findings, committedLocalFile(t, rel, covered))
			continue
		}
		if _, err := os.Stat(filepath.Join(t.ProjectDir, rel)); err != nil {
			continue
		}
		if gitignoreExists && isGitignored(rules, rel) {
			continue
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG013",
			Severity: finding.Warn,
			File:     filepath.Join(t.ProjectDir, ".gitignore"),
			Message:  rel + " exists in the repository but is not covered by .gitignore — committing it would leak personal config or developer-specific instructions to the team. Add the path (or a matching pattern) to .gitignore; if the file is already committed, also run git rm --cached " + rel + ".",
		})
	}
	return findings
}

// committedLocalFile is the finding for a local file the git index tracks.
func committedLocalFile(t *Target, rel string, covered bool) finding.Finding {
	fix := "Run git rm --cached " + rel + " and add the path to .gitignore."
	if covered {
		fix = ".gitignore already covers it, but that does not untrack a committed file: run git rm --cached " + rel + "."
	}
	return finding.Finding{
		RuleID:   "CFG013",
		Severity: finding.Warn,
		File:     filepath.Join(t.ProjectDir, rel),
		Message:  rel + " is committed to the repository — it holds personal config or developer-specific instructions (often with absolute home paths) that every clone now gets. " + fix,
	}
}

// --- minimal gitignore support ----------------------------------------------
//
// Real gitignore semantics are large; we only need the subset that covers the
// patterns the issue lists: literal paths, `*` wildcards, basename-only
// patterns matching any directory depth, and leading-`!` negation.
// `**` is not supported (none of the documented "covering" patterns use it).

type gitignoreRule struct {
	pattern string
	negate  bool
}

func loadGitignoreRules(path string) ([]gitignoreRule, bool) {
	data, err := scanroot.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false
		}
		return nil, false
	}
	return parseGitignoreRules(data), true
}

func parseGitignoreRules(data []byte) []gitignoreRule {
	var out []gitignoreRule
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		r := gitignoreRule{}
		if strings.HasPrefix(line, "!") {
			r.negate = true
			line = line[1:]
		}
		line = strings.TrimSuffix(line, "/")
		r.pattern = line
		out = append(out, r)
	}
	return out
}

// isGitignored applies the rules in order, last-match-wins (the gitignore
// convention), and returns whether the project-relative path is ignored.
func isGitignored(rules []gitignoreRule, relPath string) bool {
	ignored := false
	for _, r := range rules {
		if gitignoreMatch(r.pattern, relPath) {
			ignored = !r.negate
		}
	}
	return ignored
}

func gitignoreMatch(pattern, relPath string) bool {
	if pattern == "" {
		return false
	}
	pat := strings.TrimPrefix(pattern, "/")
	if strings.Contains(pat, "/") {
		ok, _ := filepath.Match(pat, relPath)
		return ok
	}
	// No slash: gitignore matches the basename at any depth.
	ok, _ := filepath.Match(pat, filepath.Base(relPath))
	return ok
}
