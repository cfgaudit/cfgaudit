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

// envSecretPaths are representative .env secret paths an exception rule must
// re-expose to count as carving this class. .env.example / .env.sample are
// deliberately absent: a Read(!**/.env.example) carve is a safe template, not the
// secret file, so it must not read as exposing .env.
var envSecretPaths = []string{".env", ".env.local", "config/.env"}

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
	if denyReadsCovered(deny, envCoverRe, envSecretPaths, t.ClaudeVersion) {
		return nil
	}
	return []finding.Finding{{
		RuleID:   "CFG041",
		Severity: finding.Error,
		File:     t.SettingsFile,
		Message:  "permissions.deny does not restrict access to .env files — Claude can read credentials they contain; add \"Read(**/.env)\" and \"Read(**/.env.*)\" to permissions.deny" + userScopeNote(t),
	}}
}
