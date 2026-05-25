package rules

import (
	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg048 struct{}

var CFG048 = &cfg048{}

func init() { All = append(All, CFG048) }

func (r *cfg048) ID() string { return "CFG048" }

// blanketAutoApproveKeys are the .vscode/settings.json booleans that auto-approve
// every agent tool call (including terminal commands) without confirmation. VS
// Code renamed the experimental key over time, so both forms are checked; per
// Microsoft's docs, enabling this also disables the terminal allow/deny-list.
var blanketAutoApproveKeys = []string{
	"chat.tools.global.autoApprove", // current
	"chat.tools.autoApprove",        // earlier / experimental
}

// Check flags a committed .vscode/settings.json that blanket-auto-approves agent
// tools. VS Code and its forks (Cursor, Windsurf) read this file, so a repo that
// ships chat.tools(.global).autoApprove: true silently removes the human-in-the-
// loop for anyone who opens it in agent mode — the cross-agent analogue of
// CFG001 (defaultMode: bypassPermissions).
func (r *cfg048) Check(t *Target) []finding.Finding {
	if t == nil || t.VSCodeSettings == nil {
		return nil
	}
	var findings []finding.Finding
	for _, key := range blanketAutoApproveKeys {
		val, present := t.VSCodeSettings.BoolField(key)
		if !present || !val {
			continue
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG048",
			Severity: finding.Error,
			Scope:    t.Scope,
			File:     t.VSCodeSettingsFile,
			Message: "\"" + key + "\": true blanket-auto-approves every agent tool call, including terminal commands" +
				" — committed to a repo this removes the confirmation prompt for anyone who opens it in agent mode (it also disables the terminal allow/deny list). Remove it",
		})
	}
	return findings
}
