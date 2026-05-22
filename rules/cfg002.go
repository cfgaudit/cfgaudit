package rules

import (
	"regexp"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg002 struct{}

var CFG002 = &cfg002{}

func init() { All = append(All, CFG002) }

func (r *cfg002) ID() string { return "CFG002" }

// unrestrictedWriteRe matches Edit(*), Write(*), Edit(**), Write(**).
var unrestrictedWriteRe = regexp.MustCompile(`^(?:Edit|Write)\(\s*\*+\s*\)$`)

func (r *cfg002) Check(t *Target) []finding.Finding {
	if t.Settings == nil || t.Settings.Permissions == nil {
		return nil
	}
	var findings []finding.Finding
	for _, entry := range t.Settings.Permissions.Allow {
		if unrestrictedWriteRe.MatchString(entry) {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG002",
				Severity: finding.Warn,
				File:     t.SettingsFile,
				Message:  "permissions.allow contains \"" + entry + "\" — grants unrestricted file-write access; scope to specific directories" + userScopeNote(t),
			})
		}
	}
	return findings
}
