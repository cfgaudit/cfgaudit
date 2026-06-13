package rules

import (
	"regexp"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

type cfg074 struct{}

var CFG074 = &cfg074{}

func init() { All = append(All, CFG074) }

func (r *cfg074) ID() string { return "CFG074" }

// fullCommitSHARe matches a full 40-hex git commit SHA — the only ref form that
// pins a skill source to immutable content. A branch, tag, or short SHA is mutable.
var fullCommitSHARe = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

// Check flags a committed skills-lock.json (vercel-labs/skills CLI) entry that
// pulls skill content from a remote source without pinning it to a commit SHA.
// A skill is instruction text loaded into the agent's trusted context; with an
// unpinned source, whoever controls the upstream repo can change what every
// contributor's agent reads on the next sync — the skills-CLI analogue of an
// unpinned MCP package (CFG017) or auto-loaded plugin source. Local sources carry
// no remote trust edge and are not flagged.
func (r *cfg074) Check(t *Target) []finding.Finding {
	if t == nil || t.SkillsLock == nil {
		return nil
	}
	var findings []finding.Finding
	for _, alias := range sortedSkillAliases(t.SkillsLock.Skills) {
		e := t.SkillsLock.Skills[alias]
		if strings.EqualFold(e.SourceType, "local") || strings.TrimSpace(e.Source) == "" {
			continue // on-disk skill (or no source) — no remote trust edge
		}
		ref := strings.TrimSpace(e.Ref)
		if fullCommitSHARe.MatchString(ref) {
			continue // pinned to an immutable commit
		}
		clause := "does not pin a ref"
		if ref != "" {
			clause = "pins ref to \"" + ref + "\", a branch/tag rather than an immutable commit SHA"
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG074",
			Severity: finding.Warn,
			File:     t.SkillsLockFile,
			Message: "skills." + alias + " pulls skill content from \"" + e.Source + "\" but " + clause +
				" — a committed skills-lock.json with an unpinned source is a moving target: whoever controls the upstream repo can change the skill (instruction) text injected into every contributor's agent context on the next sync. Pin ref to a full commit SHA" +
				userScopeNote(t),
		})
	}
	return findings
}

// sortedSkillAliases returns the skill aliases (local names) of m in lexical order
// so findings are emitted deterministically.
func sortedSkillAliases(m map[string]parser.SkillEntry) []string {
	aliases := make([]string, 0, len(m))
	for a := range m {
		aliases = append(aliases, a)
	}
	sort.Strings(aliases)
	return aliases
}
