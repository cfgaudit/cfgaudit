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
// Scoped to real subagent files — Claude Code's .claude/agents/*.md and xAI
// Grok's .grok/agents/*.md, which use the same camelCase permissionMode field.
// The field is meaningless in a CLAUDE.md or a skill, and Claude Code documents
// that it is ignored for plugin subagents, so flagging it elsewhere would be a
// false positive.
//
// Per-agent value honoring: Claude Code applies every mode below, but Grok's
// source documents that "only BypassPermissions is wired at spawn; others are
// forward-compat", so for a Grok agent only bypassPermissions is flagged —
// reporting a mode Grok currently ignores would be a false positive (the same
// discipline as CFG087 and the Codex project-layer denylist).
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

// agentFileKind reports which agent a Markdown file is a subagent definition for
// ("Claude" for .claude/agents/*.md, "Grok" for .grok/agents/*.md), or "" when it
// is not a subagent file. Both agents read the same camelCase permissionMode.
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
	}
	return ""
}
