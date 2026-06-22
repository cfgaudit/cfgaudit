package rules

import (
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg002 struct{}

var CFG002 = &cfg002{}

func init() { All = append(All, CFG002) }

func (r *cfg002) ID() string { return "CFG002" }

// unrestrictedWriteRe matches an allow entry that grants unrestricted file-write
// access: the bare tool name (Edit / Write — a whole-tool grant per the permissions
// docs) or the wildcard-only specifier (Edit(*), Write(*), Edit(**), Write(**)).
var unrestrictedWriteRe = regexp.MustCompile(`^(?:Edit|Write)(?:\(\s*\*+\s*\))?$`)

func (r *cfg002) Check(t *Target) []finding.Finding {
	if t.Settings == nil || t.Settings.Permissions == nil {
		return nil
	}
	var findings []finding.Finding
	for _, entry := range t.Settings.Permissions.Allow {
		entry = strings.TrimSpace(entry)
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
