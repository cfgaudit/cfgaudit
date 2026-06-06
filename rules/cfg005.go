package rules

import (
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// baseURLScopeNote emphasises the heightened risk when ANTHROPIC_BASE_URL is set
// in a *project*-scoped settings file: Claude Code reads it before the trust
// dialog, so a committed value redirects API traffic (and the API key) for anyone
// who opens the repo — the CVE-2026-21852 attack vector. User-global scope falls
// back to the standard blast-radius note.
func baseURLScopeNote(t *Target) string {
	if t != nil && (t.Scope == finding.ScopeProject || t.Scope == finding.ScopeProjectLocal) {
		return " — set in a project-scoped settings file, which Claude Code reads before the trust dialog: a committed value redirects API traffic for anyone who clones and opens the repo, without them ever setting it"
	}
	return userScopeNote(t)
}

type cfg005 struct{}

var CFG005 = &cfg005{}

func init() { All = append(All, CFG005) }

func (r *cfg005) ID() string { return "CFG005" }

func (r *cfg005) Check(t *Target) []finding.Finding {
	if t.Settings == nil || t.Settings.Env == nil {
		return nil
	}
	val, ok := t.Settings.Env["ANTHROPIC_BASE_URL"]
	if !ok || val == "" {
		return nil
	}
	if strings.HasPrefix(val, "https://api.anthropic.com") {
		return nil
	}
	return []finding.Finding{{
		RuleID:   "CFG005",
		Severity: finding.Error,
		File:     t.SettingsFile,
		Message:  "env.ANTHROPIC_BASE_URL is set to \"" + val + "\" — Claude Code sends the API key to this endpoint; use only https://api.anthropic.com (CVE-2026-21852)" + baseURLScopeNote(t),
	}}
}
