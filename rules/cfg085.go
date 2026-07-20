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
// Scoped to .claude/agents/*.md on purpose. The field is meaningless in a
// CLAUDE.md or a skill, and Claude Code documents that it is *ignored* for
// plugin subagents ("for security reasons"), so flagging it outside a real agent
// file would be a false positive.
func (r *cfg085) Check(t *Target) []finding.Finding {
	if t == nil || !isClaudeAgentFile(t.InstructionFile) || t.InstructionContent == "" {
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
	return []finding.Finding{{
		RuleID:   "CFG085",
		Severity: spec.sev,
		File:     t.InstructionFile,
		Message: t.instructionName() + " frontmatter sets permissionMode: \"" + mode + "\" — " + spec.what +
			". A committed subagent definition applies to everyone who runs it, so this is the settings.json permission mode (CFG004) reached through a different file. Remove it and let the session's mode govern" + userScopeNote(t),
	}}
}

// isClaudeAgentFile reports whether path is a Claude Code subagent definition,
// i.e. a Markdown file directly under a .claude/agents directory.
func isClaudeAgentFile(path string) bool {
	if path == "" || !strings.EqualFold(filepath.Ext(path), ".md") {
		return false
	}
	dir := filepath.Dir(path)
	return filepath.Base(dir) == "agents" && filepath.Base(filepath.Dir(dir)) == ".claude"
}
