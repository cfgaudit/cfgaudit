package rules

import (
	"regexp"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg028 struct{}

var CFG028 = &cfg028{}

func init() { All = append(All, CFG028) }

func (r *cfg028) ID() string { return "CFG028" }

// trustFile matches the Claude Code trust/config files a command must not rewrite.
const trustFile = `(?:CLAUDE\.md|CLAUDE\.local\.md|settings\.local\.json|settings\.json|\.mcp\.json|\.claude/)`

var trustFileRe = regexp.MustCompile(trustFile)

// trustWritePatterns detect a write whose target is a trust file:
//   - redirection (> / >>) or tee into one
//   - in-place stream edit (sed -i) of one
//   - cp / mv / install / ln / dd with one as the final (destination) argument
var trustWritePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?:>>?|\btee\b(?:\s+-a)?\s+)\s*['"]?\S*` + trustFile),
	regexp.MustCompile(`\bsed\b[^|;&]*-i\b[^|;&]*` + trustFile),
	regexp.MustCompile(`\b(?:cp|mv|install|ln|dd)\b[^|;&]*` + trustFile + `['"]?\s*(?:$|[|;&])`),
}

// Check flags command sites that write to a Claude trust/config file. Rewriting
// CLAUDE.md / settings.json / .mcp.json / .claude/ from a hook or helper is a
// self-perpetuating prompt-injection and persistence vector: it can re-inject
// hidden instructions or re-enable dangerous settings on every session, and
// survive cleanup by restoring itself. Heuristic and static — it matches the
// common write idioms, not obfuscated writes (e.g. a path built from variables).
func (r *cfg028) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	for _, site := range commandSites(t.Settings) {
		if !matchesAny(trustWritePatterns, site.Command) {
			continue
		}
		target := trustFileRe.FindString(site.Command)
		findings = append(findings, finding.Finding{
			RuleID:   "CFG028",
			Severity: finding.Error,
			File:     t.SettingsFile,
			Message: site.Label + " writes to the Claude trust/config file \"" + target +
				"\" — a self-perpetuating prompt-injection / persistence vector: it can re-inject hidden instructions or re-enable dangerous settings every session and restore itself after cleanup. A hook should never modify Claude's own configuration" + userScopeNote(t),
		})
	}
	return findings
}

func matchesAny(res []*regexp.Regexp, s string) bool {
	for _, re := range res {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}
