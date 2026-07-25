package rules

import (
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg091 struct{}

var CFG091 = &cfg091{}

func init() { All = append(All, CFG091) }

func (r *cfg091) ID() string { return "CFG091" }

// Check flags a committed qwen-code .qwen/settings.json whose tools.approvalMode
// is "yolo" — the mode that auto-approves every tool call, shell included, with no
// confirmation prompt (verified: needsConfirmation returns false for YOLO on all
// tools but ask_user_question). It is qwen's analogue of Claude Code's
// defaultMode: bypassPermissions (CFG004) and Gemini's defaultApprovalMode: yolo
// (CFG060), reached through a tools.-nested key.
//
// Only "yolo" is flagged, and the reason is a deliberate scoping decision:
//
//   - "auto" is qwen's SHIPPED DEFAULT (schema and runtime default is AUTO), so a
//     committed "auto" does not escalate beyond a fresh install — flagging it would
//     flag qwen's product posture, not a committed footgun. It is also not a blanket
//     approve: it auto-accepts edits and a safe read-only allowlist, and routes
//     shell through a destructive-command guard plus a classifier that blocks
//     destructive actions.
//   - "auto-edit" auto-approves only edit/info confirmations and still prompts for
//     shell, so it is STRICTER than qwen's "auto" default — committing it is a
//     de-escalation, not a footgun.
//   - tools.autoAccept is vestigial (no consumer in the approval path), so it is
//     not read at all.
//
// Severity backdrop: qwen ships folder trust DISABLED by default
// (security.folderTrust.enabled ?? false), so a workspace is trusted-by-default and
// the untrusted-folder downgrade (which would force approvalMode back to "default")
// does not fire. A committed "yolo" therefore takes effect for everyone who opens
// the repo, unprompted — the inverse of Cursor/Codex/Grok, which gate project
// config on trust.
func (r *cfg091) Check(t *Target) []finding.Finding {
	if t == nil || t.Qwen == nil || t.Qwen.Tools == nil {
		return nil
	}
	if strings.ToLower(strings.TrimSpace(t.Qwen.Tools.ApprovalMode)) != "yolo" {
		return nil
	}
	return []finding.Finding{{
		RuleID:   "CFG091",
		Severity: finding.Error,
		Scope:    t.Scope,
		File:     t.QwenFile,
		Message: "qwen tools.approvalMode is \"yolo\" — it auto-approves every tool call, shell commands included, with no confirmation prompt, " +
			"the qwen equivalent of Claude Code's defaultMode: bypassPermissions (CFG004). qwen ships folder trust off by default, so a committed " +
			".qwen/settings.json applies to everyone who opens the repo without a trust prompt; use \"default\" or \"plan\"" + userScopeNote(t),
	}}
}
