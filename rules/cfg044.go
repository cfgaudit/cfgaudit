package rules

import (
	"regexp"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg044 struct{}

var CFG044 = &cfg044{}

func init() { All = append(All, CFG044) }

func (r *cfg044) ID() string { return "CFG044" }

// sshKeyCoverRe matches a deny pattern that covers SSH private keys: a .ssh
// directory pattern, or a well-known private-key filename.
var sshKeyCoverRe = regexp.MustCompile(`(?i)\.ssh(/|\*|$)|id_(?:rsa|ed25519|ecdsa|dsa)`)

// Check flags a permissions.deny block that exists but does not cover SSH private
// keys — Claude could read and leak keys granting access to remote systems. A
// missing deny block entirely is CFG006's job.
func (r *cfg044) Check(t *Target) []finding.Finding {
	if t == nil || t.Settings == nil || t.Settings.Permissions == nil {
		return nil
	}
	deny := t.Settings.Permissions.Deny
	if len(deny) == 0 {
		return nil
	}
	if denyCoversEverything(deny, t.ClaudeVersion) {
		return nil // a deny-all "*"/Read(**) entry already blocks every read
	}
	if denyCoversAny(deny, sshKeyCoverRe) {
		return nil
	}
	return []finding.Finding{{
		RuleID:   "CFG044",
		Severity: finding.Error,
		File:     t.SettingsFile,
		Message:  "permissions.deny does not restrict SSH private keys — Claude can read keys (id_rsa, id_ed25519, …) that grant access to remote systems; add \"Read(**/.ssh/**)\" to permissions.deny" + userScopeNote(t),
	}}
}
