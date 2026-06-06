package rules

import "github.com/cfgaudit/cfgaudit/internal/finding"

type cfg062 struct{}

var CFG062 = &cfg062{}

func init() { All = append(All, CFG062) }

func (r *cfg062) ID() string { return "CFG062" }

// Check flags a Gemini CLI settings.json that explicitly allows installing
// extensions from arbitrary Git repositories (security.blockGitExtensions:
// false) without an allow-list to constrain them — a committed supply-chain
// footgun: any repo the agent is pointed at can ship executable extension code.
// Only fires on an explicit `false` (not the absence of the field) and only when
// security.allowedExtensions does not narrow what may be installed.
func (r *cfg062) Check(t *Target) []finding.Finding {
	if t == nil || t.Gemini == nil || t.Gemini.Security == nil {
		return nil
	}
	sec := t.Gemini.Security
	if sec.BlockGitExtensions == nil || *sec.BlockGitExtensions {
		return nil // absent, or explicitly blocking git extensions — fine
	}
	if len(sec.AllowedExtensions) > 0 {
		return nil // an allow-list constrains what may be installed
	}
	return []finding.Finding{{
		RuleID:   "CFG062",
		Severity: finding.Warn,
		File:     t.GeminiFile,
		Message:  "Gemini security.blockGitExtensions is false with no security.allowedExtensions allow-list — the workspace permits installing extensions from arbitrary Git repositories, a supply-chain vector (extension code runs with the agent's privileges). Set blockGitExtensions: true, or pin an allowedExtensions allow-list" + userScopeNote(t),
	}}
}
