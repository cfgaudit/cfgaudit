package rules

import (
	"path/filepath"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

type cfg085 struct{}

var CFG085 = &cfg085{}

func init() { All = append(All, CFG085) }

func (r *cfg085) ID() string { return "CFG085" }

// permissionModeWeakening maps a subagent frontmatter permissionMode to how it
// weakens the permission system. The documented values are default, acceptEdits,
// auto, dontAsk, bypassPermissions, plan and manual (an alias for default);
// default, plan and manual are absent here because they prompt normally.
//
// Severities mirror CFG004, which reads the same modes from settings.json:
// bypassPermissions is an error, the softer modes are warnings.
var permissionModeWeakening = map[string]struct {
	sev  finding.Severity
	what string
}{
	"bypassPermissions": {finding.Error, "disables all permission checks — the subagent runs with full autonomy and no confirmation prompts"},
	"dontAsk":           {finding.Error, "suppresses permission prompts — the subagent proceeds without asking"},
	"auto":              {finding.Warn, "hands permission decisions to the auto-mode classifier instead of prompting (see CFG079 for how its allow/deny lists can be weakened)"},
	"acceptEdits":       {finding.Warn, "auto-accepts file edits, so the subagent writes to the working tree without confirmation"},
}

// Check flags a committed subagent definition whose frontmatter weakens the
// permission mode. CFG004 covers the same modes in settings.json; a subagent
// file is the other door to the same place, and it is just as committable.
//
// Scoped to real subagent files — Claude Code's .claude/agents/*.md, xAI Grok's
// .grok/agents/*.md (both camelCase permissionMode), and qwen-code's
// .qwen/agents/*.md (native approvalMode, plus a bridged permissionMode). The
// field is meaningless in a CLAUDE.md or a skill, and Claude Code documents that
// it is ignored for plugin subagents, so flagging it elsewhere would be a false
// positive.
//
// Per-agent value honoring: Claude Code applies every mode below, but Grok's
// source documents that "only BypassPermissions is wired at spawn; others are
// forward-compat", so for a Grok agent only bypassPermissions is flagged —
// reporting a mode Grok currently ignores would be a false positive (the same
// discipline as CFG087 and the Codex project-layer denylist). qwen resolves the
// mode differently again, handled in checkQwen.
func (r *cfg085) Check(t *Target) []finding.Finding {
	if t == nil || t.InstructionContent == "" {
		return nil
	}
	kind := agentFileKind(t.InstructionFile)
	if kind == "" {
		return nil
	}
	fm, ok := parser.InstructionFrontmatter(t.InstructionContent)
	if !ok {
		return nil
	}
	if kind == "qwen" {
		return r.checkQwen(t, fm)
	}
	mode := strings.TrimSpace(fm.String("permissionMode"))
	spec, weakening := permissionModeWeakening[mode]
	if !weakening {
		return nil
	}
	if kind == "Grok" && mode != "bypassPermissions" {
		return nil // Grok wires only bypassPermissions at spawn; the rest are inert
	}

	tail := " so this is the settings.json permission mode (CFG004) reached through a different file. Remove it and let the session's mode govern"
	if kind == "Grok" {
		tail = " and Grok wires this mode at spawn, so a cloned repo runs the subagent with it. Remove it and let the session's mode govern"
	}
	return []finding.Finding{{
		RuleID:   "CFG085",
		Severity: spec.sev,
		File:     t.InstructionFile,
		Message: t.instructionName() + " frontmatter sets permissionMode: \"" + mode + "\" — " + spec.what +
			". A committed subagent definition applies to everyone who runs it," + tail + userScopeNote(t),
	}}
}

// qwenApprovalTiers maps a qwen effective approvalMode to how it weakens
// approvals. Only the weakening directions appear: default, plan and the
// subagent-only bubble mode prompt normally, so they are absent and produce no
// finding.
var qwenApprovalTiers = map[string]struct {
	sev  finding.Severity
	what string
}{
	"yolo":      {finding.Error, "runs the subagent with no confirmation prompts — full autonomy"},
	"auto-edit": {finding.Warn, "auto-accepts file edits, so the subagent writes to the working tree without confirmation"},
	"auto":      {finding.Warn, "hands permission decisions to the auto-mode classifier instead of prompting"},
}

// qwenNativeApprovalModes is qwen's ApprovalMode enum plus the subagent-only
// bubble value (isSubagentApprovalMode). An approvalMode outside this set makes
// qwen reject the whole agent file, so a present-but-invalid value is not treated
// as a configured mode.
var qwenNativeApprovalModes = map[string]bool{
	"default": true, "plan": true, "auto-edit": true, "auto": true, "yolo": true, "bubble": true,
}

// qwenPermissionBridge mirrors PERMISSION_MODE_TO_APPROVAL_MODE
// (agent-frontmatter-schema.ts): a Claude permissionMode is honoured on a
// .qwen/agents file only through this bridge, and only when approvalMode is
// unset. dontAsk maps to default because qwen preserves its restrictive intent,
// so it is NOT a weakening value here even though CFG085 treats dontAsk as one
// for a Claude file. A permissionMode outside these six keys (for example the
// common but invalid "yolo") is dropped and honours nothing.
var qwenPermissionBridge = map[string]string{
	"default":           "default",
	"plan":              "plan",
	"acceptEdits":       "auto-edit",
	"auto":              "auto-edit",
	"bypassPermissions": "yolo",
	"dontAsk":           "default",
}

// checkQwen flags a .qwen/agents file whose effective approval mode weakens
// approvals. qwen resolves the mode as `approvalMode ?? bridge(permissionMode)`:
// the native approvalMode wins, and a Claude-enum permissionMode is bridged only
// when approvalMode is unset (subagent-manager.ts, effectiveApprovalMode). A
// committed weakening value runs the subagent without prompts once the folder is
// trusted, and qwen's folder trust is off by default (CFG099), so "trusted" is
// the common state; the untrusted clamp is the vendor's own "would let the repo
// silently grant itself classifier-mediated automation" gate one prompt later.
func (r *cfg085) checkQwen(t *Target, fm *parser.Frontmatter) []finding.Finding {
	var eff, shown string
	if approval := strings.TrimSpace(fm.String("approvalMode")); approval != "" {
		if !qwenNativeApprovalModes[approval] {
			return nil // an invalid approvalMode makes qwen reject the file entirely
		}
		eff = approval
		shown = "approvalMode: \"" + approval + "\""
	} else {
		pm := strings.TrimSpace(fm.String("permissionMode"))
		bridged, ok := qwenPermissionBridge[pm]
		if !ok {
			return nil // not a bridgeable Claude enum value (e.g. permissionMode: yolo)
		}
		eff = bridged
		if bridged == pm {
			shown = "permissionMode: \"" + pm + "\""
		} else {
			shown = "permissionMode: \"" + pm + "\", which qwen bridges to approvalMode \"" + bridged + "\""
		}
	}

	spec, weakening := qwenApprovalTiers[eff]
	if !weakening {
		return nil
	}
	return []finding.Finding{{
		RuleID:   "CFG085",
		Severity: spec.sev,
		File:     t.InstructionFile,
		Message: t.instructionName() + " frontmatter sets " + shown + " — " + spec.what +
			". A committed subagent definition applies to everyone who runs it, and qwen honours a definition's mode in a trusted folder (folder trust is off by default), so a cloned repo runs the subagent with it. Remove it and let the session's mode govern" + userScopeNote(t),
	}}
}

// agentFileKind reports which agent a Markdown file is a subagent definition for
// ("Claude" for .claude/agents/*.md, "Grok" for .grok/agents/*.md, "qwen" for
// .qwen/agents/*.md), or "" when it is not a subagent file. Claude and Grok read
// the same camelCase permissionMode; qwen mirrors the Claude schema and adds a
// native approvalMode (see checkQwen).
func agentFileKind(path string) string {
	if path == "" || !strings.EqualFold(filepath.Ext(path), ".md") {
		return ""
	}
	dir := filepath.Dir(path)
	if filepath.Base(dir) != "agents" {
		return ""
	}
	switch filepath.Base(filepath.Dir(dir)) {
	case ".claude":
		return "Claude"
	case ".grok":
		return "Grok"
	case ".qwen":
		return "qwen"
	}
	return ""
}
