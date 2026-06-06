package rules

import (
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg064 struct{}

var CFG064 = &cfg064{}

func init() { All = append(All, CFG064) }

func (r *cfg064) ID() string { return "CFG064" }

// Check flags an OpenAI Codex CLI config.toml whose sandbox_mode is
// "danger-full-access" — the sandbox is disabled and tools run with full
// filesystem and network access, the Codex analog of weakening Claude Code's
// sandbox (CFG022). Combined with approval_policy: never (CFG063) this is a fully
// unattended, unsandboxed agent.
func (r *cfg064) Check(t *Target) []finding.Finding {
	if t == nil || t.Codex == nil {
		return nil
	}
	if strings.ToLower(strings.TrimSpace(t.Codex.SandboxMode)) != "danger-full-access" {
		return nil
	}
	return []finding.Finding{{
		RuleID:   "CFG064",
		Severity: finding.Error,
		File:     t.CodexFile,
		Message:  "Codex sandbox_mode is \"danger-full-access\" — tools run with no sandbox (full filesystem and network access), analogous to weakening Claude Code's sandbox (CFG022). Use \"read-only\" or \"workspace-write\"" + userScopeNote(t),
	}}
}
