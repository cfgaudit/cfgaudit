package rules

import (
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg060 struct{}

var CFG060 = &cfg060{}

func init() { All = append(All, CFG060) }

func (r *cfg060) ID() string { return "CFG060" }

// Check flags a Gemini CLI settings.json whose general.defaultApprovalMode
// auto-approves tool actions — "auto_edit" applies all edit tools without
// prompting (and "yolo", should it appear as a mode, approves everything). A
// project .gemini/settings.json committing this is the Gemini equivalent of
// Claude Code's defaultMode: bypassPermissions (CFG004): it removes the
// human-in-the-loop for everyone who opens the workspace.
func (r *cfg060) Check(t *Target) []finding.Finding {
	if t == nil || t.Gemini == nil || t.Gemini.General == nil {
		return nil
	}
	mode := strings.ToLower(strings.TrimSpace(t.Gemini.General.DefaultApprovalMode))
	if mode != "auto_edit" && mode != "yolo" {
		return nil
	}
	return []finding.Finding{{
		RuleID:   "CFG060",
		Severity: finding.Error,
		File:     t.GeminiFile,
		Message: "Gemini general.defaultApprovalMode is \"" + mode +
			"\" — it auto-approves tool actions without prompting, the Gemini equivalent of Claude Code's defaultMode: bypassPermissions (CFG004). A committed workspace config removes the human-in-the-loop for everyone who opens it; use \"default\" or \"plan\"" + userScopeNote(t),
	}}
}
