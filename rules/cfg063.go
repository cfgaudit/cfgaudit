package rules

import (
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg063 struct{}

var CFG063 = &cfg063{}

func init() { All = append(All, CFG063) }

func (r *cfg063) ID() string { return "CFG063" }

// Check flags an OpenAI Codex CLI config.toml whose approval_policy auto-approves
// commands — the Codex analog of Claude Code's defaultMode: bypassPermissions
// (CFG004). "never" never asks the user (all commands auto-approved,
// non-interactive); the deprecated "on-failure" auto-approves everything and
// only escalates on failure.
func (r *cfg063) Check(t *Target) []finding.Finding {
	if t == nil || t.Codex == nil {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(t.Codex.ApprovalPolicy)) {
	case "never":
		return []finding.Finding{{
			RuleID:   "CFG063",
			Severity: finding.Error,
			File:     t.CodexFile,
			Message:  "Codex approval_policy is \"never\" — commands are auto-approved without ever asking the user, the Codex equivalent of defaultMode: bypassPermissions (CFG004). Use \"untrusted\" or \"on-request\" to keep a human in the loop" + userScopeNote(t),
		}}
	case "on-failure":
		return []finding.Finding{{
			RuleID:   "CFG063",
			Severity: finding.Warn,
			File:     t.CodexFile,
			Message:  "Codex approval_policy is \"on-failure\" (deprecated) — all commands are auto-approved and only escalated to the user on failure. Prefer \"on-request\" so actions are approved before they run" + userScopeNote(t),
		}}
	}
	return nil
}
