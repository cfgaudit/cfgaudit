package rules

import (
	"encoding/json"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg004 struct{}

var CFG004 = &cfg004{}

func init() { All = append(All, CFG004) }

func (r *cfg004) ID() string { return "CFG004" }

// MinVersion returns the lowest Claude Code release that interprets the
// defaultMode key. The bypassPermissions value has shipped since the early
// 0.2.x series; the "auto" value was schema-validated by 2.1.91. The lower
// bound keeps both branches reachable on older installs.
func (r *cfg004) MinVersion() string { return "0.2.21" }

func (r *cfg004) Check(t *Target) []finding.Finding {
	if t.Settings == nil {
		return nil
	}
	raw, ok := t.Settings.Raw["defaultMode"]
	if !ok {
		return nil
	}
	var mode string
	if err := json.Unmarshal(raw, &mode); err != nil {
		return nil
	}
	switch mode {
	case "bypassPermissions":
		return []finding.Finding{{
			RuleID:   "CFG004",
			Severity: finding.Error,
			File:     t.SettingsFile,
			Message:  "defaultMode: \"bypassPermissions\" disables all permission checks — Claude Code runs with full autonomy and no confirmation prompts" + userScopeNote(t),
		}}
	case "auto":
		return []finding.Finding{{
			RuleID:   "CFG004",
			Severity: finding.Warn,
			File:     t.SettingsFile,
			Message:  "defaultMode: \"auto\" suppresses all confirmation prompts — review allow/deny rules carefully before enabling" + userScopeNote(t),
		}}
	}
	return nil
}
