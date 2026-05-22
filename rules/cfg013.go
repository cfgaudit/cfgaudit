package rules

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
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

	var findings []finding.Finding
	for _, rel := range sensitiveLocalFiles {
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
			Message:  rel + " exists in the repository but is not covered by .gitignore — committing it would leak personal config or developer-specific instructions to the team. Add the path (or a matching pattern) to .gitignore.",
		})
	}
	return findings
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
	data, err := os.ReadFile(path) //nolint:gosec // G304: project-relative .gitignore lookup
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
