package rules

import (
	"regexp"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg041 struct{}

var CFG041 = &cfg041{}

func init() { All = append(All, CFG041) }

func (r *cfg041) ID() string { return "CFG041" }

// envCoverRe matches a deny pattern that targets .env files: .env, .env.*,
// *.env, **/.env, **/.env.*, .env.local, etc.
var envCoverRe = regexp.MustCompile(`(?i)\.env($|[./*])`)

// Check flags a permissions.deny block that exists but does not restrict access
// to .env files — Claude could then read database passwords, API keys, and other
// credentials they contain. A missing deny block entirely is CFG006's job.
func (r *cfg041) Check(t *Target) []finding.Finding {
	if t == nil || t.Settings == nil || t.Settings.Permissions == nil {
		return nil
	}
	deny := t.Settings.Permissions.Deny
	if len(deny) == 0 {
		return nil // absent/empty deny is covered by CFG006
	}
	if denyCoversEverything(deny, t.ClaudeVersion) {
		return nil // a deny-all "*"/Read(**) entry already blocks every read
	}
	if denyCoversAny(deny, envCoverRe) {
		return nil
	}
	return []finding.Finding{{
		RuleID:   "CFG041",
		Severity: finding.Error,
		File:     t.SettingsFile,
		Message:  "permissions.deny does not restrict access to .env files — Claude can read credentials they contain; add \"Read(**/.env)\" and \"Read(**/.env.*)\" to permissions.deny" + userScopeNote(t),
	}}
}
