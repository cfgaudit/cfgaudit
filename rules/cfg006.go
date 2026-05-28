package rules

import "github.com/cfgaudit/cfgaudit/internal/finding"

type cfg006 struct{}

var CFG006 = &cfg006{}

func init() { All = append(All, CFG006) }

func (r *cfg006) ID() string { return "CFG006" }

// MinVersion returns the lowest Claude Code release where permissions.deny is
// honoured. Unlike the presence-based rules, CFG006 is absence-based — it fires
// when the deny guardrail is *missing*, which is only meaningful on a version
// that supports deny. That makes version-gating the correct tool here (it would
// suppress a misleading "deny absent" finding on a pre-deny release). The deny
// list is foundational and present in every observed release, so in practice the
// gate is a no-op; it is declared because the gate is semantically right, not for
// uniformity.
func (r *cfg006) MinVersion() string { return "0.2.21" }

func (r *cfg006) Check(t *Target) []finding.Finding {
	if t.Settings == nil || t.Settings.Permissions == nil {
		return nil
	}
	if len(t.Settings.Permissions.Deny) > 0 {
		return nil
	}
	// A settings.local.json need not repeat the project deny list: Claude Code
	// merges it with the sibling settings.json, whose deny rules still apply.
	if t.SiblingDeny {
		return nil
	}
	return []finding.Finding{{
		RuleID:   "CFG006",
		Severity: finding.Warn,
		File:     t.SettingsFile,
		Message:  "permissions.deny is absent or empty — no guardrails block destructive operations (rm -rf, git push --force, etc.); add explicit denylist entries" + userScopeNote(t),
	}}
}
