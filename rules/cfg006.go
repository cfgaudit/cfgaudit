package rules

import "github.com/cfgaudit/cfgaudit/internal/finding"

type cfg006 struct{}

var CFG006 = &cfg006{}

func init() { All = append(All, CFG006) }

func (r *cfg006) ID() string { return "CFG006" }

// MinVersion returns the lowest Claude Code release where permissions.deny is
// honoured. The deny list is a foundational feature present in every observed
// release; the gate is effectively a no-op but is declared for uniformity.
func (r *cfg006) MinVersion() string { return "0.2.21" }

func (r *cfg006) Check(t *Target) []finding.Finding {
	if t.Settings == nil || t.Settings.Permissions == nil {
		return nil
	}
	if len(t.Settings.Permissions.Deny) > 0 {
		return nil
	}
	return []finding.Finding{{
		RuleID:   "CFG006",
		Severity: finding.Warn,
		File:     t.SettingsFile,
		Message:  "permissions.deny is absent or empty — no guardrails block destructive operations (rm -rf, git push --force, etc.); add explicit denylist entries" + userScopeNote(t),
	}}
}
