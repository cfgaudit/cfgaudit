package rules

import (
	"path/filepath"
	"sort"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg102 struct{}

var CFG102 = &cfg102{}

func init() { All = append(All, CFG102) }

func (r *cfg102) ID() string { return "CFG102" }

// Check flags a skills directory where two committed SKILL.md files claim the
// same frontmatter name. One of them is silently dropped.
//
// Measured against Copilot CLI 1.0.80 with `copilot skill list`, which resolves
// the real registry. Two .github/skills/<dir>/SKILL.md files declaring
// `name: deploy` produce exactly ONE listed skill: the one in the
// alphabetically first directory. Verified in both directions, with the winner
// placed first and last alphabetically. The loser is not listed, not warned
// about, and not reachable under any name.
//
// The skill's name comes from the frontmatter and the directory contributes
// nothing to it (#500), so nothing in the tree tells a reader which of the two
// directories is dead. A repository can therefore add a skill that replaces one
// contributors already rely on, and the only visible difference is a directory
// name that sorts earlier.
//
// This is the collision that made a rule possible at all. #501 could not report
// a committed skill shadowing a BUILT-IN one, because that needs a list of what
// the agent ships and the set is version-dependent. A collision between two
// committed files needs no such list: both sides are in the scanned tree.
//
// Reported at warn. The shadowing is silent and real, but a duplicate name is
// also a plain authoring mistake, and cfgaudit cannot tell the two apart from
// the files alone.
func (r *cfg102) Check(t *Target) []finding.Finding {
	if t == nil || len(t.SkillCollisions) == 0 {
		return nil
	}
	names := make([]string, 0, len(t.SkillCollisions))
	for name := range t.SkillCollisions {
		names = append(names, name)
	}
	sort.Strings(names)

	var findings []finding.Finding
	for _, name := range names {
		entries := t.SkillCollisions[name]
		if len(entries) < 2 {
			continue
		}
		winner := entries[0]
		losers := make([]string, 0, len(entries)-1)
		for _, e := range entries[1:] {
			losers = append(losers, e.Dir)
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG102",
			Severity: finding.Warn,
			Scope:    t.Scope,
			File:     filepath.Join(t.SkillCollisionRoot, winner.Dir, "SKILL.md"),
			Message: "two or more committed skills in " + t.SkillCollisionRoot + " declare the same frontmatter name \"" + name +
				"\": " + quoteList(append([]string{winner.Dir}, losers...)) +
				". Only one is loaded, the one whose directory sorts first, so " + quoteList(losers) +
				" is silently dropped with no warning and under no other name. The skill's name comes from the frontmatter and the directory contributes nothing to it, so nothing in the tree shows which copy is dead. Give each skill a distinct name" + userScopeNote(t),
		})
	}
	return findings
}
