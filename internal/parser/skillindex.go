package parser

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// SkillFileEntry is one SKILL.md found under a skills root, with the name it
// registers under. Named apart from SkillEntry, which is the skills-lock.json
// source record in skills.go.
type SkillFileEntry struct {
	// Path is the SKILL.md file.
	Path string
	// Dir is the immediate directory holding it, which is what decides a
	// collision: the alphabetically first one wins.
	Dir string
	// Name is the frontmatter name the skill registers under.
	Name string
}

// skillNameRe pulls the frontmatter name out of a SKILL.md, matching the
// derivation Copilot uses (a single-line `name:` with optional quotes).
var skillNameRe = regexp.MustCompile(`(?m)^name:\s*["']?([^"'\n]+?)["']?\s*$`)

// SkillNameCollisions groups the SKILL.md files under one skills root by the
// name they register, returning only the names claimed more than once, sorted.
//
// Measured against Copilot CLI 1.0.80: two `.github/skills/<dir>/SKILL.md` files
// declaring the same frontmatter name produce exactly ONE listed skill. The
// alphabetically first directory wins and the other is dropped with no warning
// and no listing at all. Verified in both directions, with the winner placed
// first and last alphabetically.
//
// Only entries with a frontmatter name are indexed. A file without one falls
// back to its directory name, which cannot collide with another directory.
func SkillNameCollisions(root string) (map[string][]SkillFileEntry, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	byName := map[string][]SkillFileEntry{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		path := filepath.Join(root, e.Name(), "SKILL.md")
		data, err := os.ReadFile(path) // #nosec G304 -- path is derived from a user-supplied scan directory
		if err != nil {
			continue
		}
		name := skillNameOf(string(data))
		if name == "" {
			continue
		}
		byName[name] = append(byName[name], SkillFileEntry{Path: path, Dir: e.Name(), Name: name})
	}
	out := map[string][]SkillFileEntry{}
	for name, list := range byName {
		if len(list) < 2 {
			continue
		}
		sort.Slice(list, func(i, j int) bool { return list[i].Dir < list[j].Dir })
		out[name] = list
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// skillNameOf extracts the frontmatter name, or "" when the file has no
// frontmatter or no name in it.
func skillNameOf(content string) string {
	c := strings.ReplaceAll(content, "\r\n", "\n")
	if !strings.HasPrefix(strings.TrimLeft(c, "\uFEFF \t\n"), "---") {
		return ""
	}
	i := strings.Index(c, "---")
	end := strings.Index(c[i+3:], "\n---")
	if end < 0 {
		return ""
	}
	m := skillNameRe.FindStringSubmatch(c[i+3 : i+3+end])
	if m == nil {
		return ""
	}
	return strings.TrimSpace(m[1])
}
