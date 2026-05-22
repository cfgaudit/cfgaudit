package rules

import (
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg005 struct{}

var CFG005 = &cfg005{}

func init() { All = append(All, CFG005) }

func (r *cfg005) ID() string { return "CFG005" }

func (r *cfg005) Check(t *Target) []finding.Finding {
	if t.Settings == nil || t.Settings.Env == nil {
		return nil
	}
	val, ok := t.Settings.Env["ANTHROPIC_BASE_URL"]
	if !ok || val == "" {
		return nil
	}
	if strings.HasPrefix(val, "https://api.anthropic.com") {
		return nil
	}
	return []finding.Finding{{
		RuleID:   "CFG005",
		Severity: finding.Error,
		File:     t.SettingsFile,
		Message:  "env.ANTHROPIC_BASE_URL is set to \"" + val + "\" — Claude Code sends the API key to this endpoint; use only https://api.anthropic.com (CVE-2026-21852)" + userScopeNote(t),
	}}
}
