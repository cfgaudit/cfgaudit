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

// fullCommitSHARe matches a full git commit SHA — 40-hex (SHA-1) or 64-hex
// (SHA-256). A bare branch or tag is mutable; a full SHA is an immutable pin.
var fullCommitSHARe = regexp.MustCompile(`^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$`)

// Check flags a committed skills-lock.json (vercel-labs/skills CLI) entry that
// pulls skill content from a remote source with **no integrity pin at all**. A
// skill is instruction text loaded into the agent's trusted context; with an
// unpinned, unverified source, whoever controls the upstream repo can change what
// every contributor's agent reads on the next sync — the skills-CLI analogue of an
// unpinned MCP package (CFG017) or auto-loaded plugin source.
//
// The skills CLI normally records integrity when it installs (a `computedHash`
// content hash, or a resolved `commit` + `integrity` hash) — any of those pins the
// content and is NOT flagged, which is the overwhelmingly common case. Only an
// entry that carries a remote source but none of those integrity fields (and no
// full-SHA ref) is reported. Local sources carry no remote trust edge.
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
		if skillEntryPinned(e) {
			continue // content is pinned by a commit SHA or a content hash
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG074",
			Severity: finding.Warn,
			File:     t.SkillsLockFile,
			Message: "skills." + alias + " pulls skill content from \"" + e.Source + "\" with no integrity pin" +
				" — no resolved commit SHA, computedHash, or integrity hash, so the fetched skill (instruction) text is unverified: whoever controls the upstream repo can change it under every contributor on the next sync. Re-install from a released/pinned version so the lock file records a content hash" +
				userScopeNote(t),
		})
	}
	return findings
}

// skillEntryPinned reports whether a skill entry's content is pinned to something
// immutable: a content hash (computedHash / integrity) or a full resolved commit
// SHA (in ref or commit). A bare branch/tag ref alone does not pin.
func skillEntryPinned(e parser.SkillEntry) bool {
	if strings.TrimSpace(e.ComputedHash) != "" || strings.TrimSpace(e.Integrity) != "" {
		return true
	}
	return fullCommitSHARe.MatchString(strings.TrimSpace(e.Ref)) ||
		fullCommitSHARe.MatchString(strings.TrimSpace(e.Commit))
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
