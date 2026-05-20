package rules

import (
	"encoding/json"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg007 struct{}

var CFG007 = &cfg007{}

func init() { All = append(All, CFG007) }

func (r *cfg007) ID() string { return "CFG007" }

func (r *cfg007) Check(t *Target) []finding.Finding {
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
			RuleID:   "CFG007",
			Severity: finding.Error,
			File:     t.SettingsFile,
			Message:  "defaultMode: \"bypassPermissions\" disables all permission checks — Claude Code runs with full autonomy and no confirmation prompts",
		}}
	case "auto":
		return []finding.Finding{{
			RuleID:   "CFG007",
			Severity: finding.Warn,
			File:     t.SettingsFile,
			Message:  "defaultMode: \"auto\" suppresses all confirmation prompts — review allow/deny rules carefully before enabling",
		}}
	}
	return nil
}
