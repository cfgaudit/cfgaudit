package rules

import (
	"regexp"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg001 struct{}

var CFG001 = &cfg001{}

func init() { All = append(All, CFG001) }

func (r *cfg001) ID() string { return "CFG001" }

// unrestrictedBashRe matches Bash(*) and Bash(**) — the glob argument is only wildcards.
var unrestrictedBashRe = regexp.MustCompile(`^Bash\(\s*\*+\s*\)$`)

func (r *cfg001) Check(t *Target) []finding.Finding {
	if t.Settings == nil || t.Settings.Permissions == nil {
		return nil
	}
	var findings []finding.Finding
	for _, entry := range t.Settings.Permissions.Allow {
		if unrestrictedBashRe.MatchString(entry) {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG001",
				Severity: finding.Error,
				File:     t.SettingsFile,
				Message:  "permissions.allow contains \"" + entry + "\" — grants unrestricted shell access; scope to specific commands" + userScopeNote(t),
			})
		}
	}
	return findings
}
