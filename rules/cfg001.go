package rules

import (
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg001 struct{}

var CFG001 = &cfg001{}

func init() { All = append(All, CFG001) }

func (r *cfg001) ID() string { return "CFG001" }

// unrestrictedBashRe matches an allow entry that grants unrestricted shell access:
// the bare tool name (Bash / PowerShell — equivalent to a whole-tool grant per the
// permissions docs) or the wildcard-only specifier (Bash(*), Bash(**)). PowerShell
// is an equivalent arbitrary-command surface, so it is covered the same way. Tool
// names are matched case-sensitively, as Claude Code matches the canonical name.
var unrestrictedBashRe = regexp.MustCompile(`^(?:Bash|PowerShell)(?:\(\s*\*+\s*\))?$`)

func (r *cfg001) Check(t *Target) []finding.Finding {
	if t.Settings == nil || t.Settings.Permissions == nil {
		return nil
	}
	var findings []finding.Finding
	for _, entry := range t.Settings.Permissions.Allow {
		entry = strings.TrimSpace(entry)
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
