// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path/filepath"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

type cfg051 struct{}

var CFG051 = &cfg051{}

func init() { All = append(All, CFG051) }

func (r *cfg051) ID() string { return "CFG051" }

// Check flags a model-facing instruction file (skill SKILL.md, slash command, or
// subagent) whose YAML frontmatter grants overly broad tool access via
// allowed-tools. A committed command/skill that grants unrestricted shell or all
// tools lets it run anything when invoked — the frontmatter analogue of the
// permission-breadth rules (CFG002/CFG006). A grant cancelled by disallowed-tools
// is not flagged.
func (r *cfg051) Check(t *Target) []finding.Finding {
	if t == nil || t.InstructionContent == "" || isDevinAgentProfile(t.InstructionFile) {
		return nil
	}
	fm, ok := parser.InstructionFrontmatter(t.InstructionContent)
	if !ok {
		return nil
	}
	allowed := fm.StringList("allowed-tools")
	if len(allowed) == 0 {
		allowed = fm.StringList("allowedTools") // tolerate camelCase variant
	}
	if len(allowed) == 0 {
		return nil
	}
	disallowed := append(fm.StringList("disallowed-tools"), fm.StringList("disallowedTools")...)

	sev, what := analyzeAllowedTools(allowed, disallowed)
	if what == "" {
		return nil
	}
	return []finding.Finding{{
		RuleID:   "CFG051",
		Severity: sev,
		File:     t.InstructionFile,
		Message: t.instructionName() + " frontmatter allowed-tools " + what +
			" — a committed command/skill with this grant can run it when invoked; narrow allowed-tools to the specific tools it needs" + userScopeNote(t),
	}}
}

// analyzeAllowedTools classifies an allowed-tools grant, honouring disallowed-tools.
// Returns (severity, reason) or ("", "") when the grant is acceptably scoped.
func analyzeAllowedTools(allowed, disallowed []string) (finding.Severity, string) {
	disallow := make(map[string]bool, len(disallowed))
	for _, d := range disallowed {
		disallow[strings.ToLower(strings.TrimSpace(d))] = true
	}
	cancelled := func(tool string) bool { return disallow[strings.ToLower(tool)] }

	for _, raw := range allowed {
		tool := strings.TrimSpace(raw)
		low := strings.ToLower(tool)
		switch {
		case tool == "*" || low == "all" || low == "full":
			if !cancelled(tool) {
				return finding.Error, "grants all tools (\"" + tool + "\") — unrestricted tool access"
			}
		// "exec" is Devin CLI's command tool (#644): its skill docs list the tool
		// names read, edit, grep, glob and exec, and say allowed-tools entries
		// are "auto-approved (no permission prompt) while the skill runs", so a
		// bare exec is unrestricted shell. "exec(*)" is the same grant.
		case low == "bash" || low == "bash(*)" || low == "shell" || low == "execute" || low == "exec" || low == "exec(*)":
			// Unrestricted shell: broad and worth review, but a common, often
			// legitimate declaration for skills that genuinely need a shell — warn,
			// not error (which is reserved for total */all access above).
			if !cancelled(tool) {
				example := "Bash(npm test)"
				if strings.HasPrefix(low, "exec") {
					example = "Exec(npm test)"
				}
				return finding.Warn, "grants unrestricted shell access (\"" + tool + "\") — scope it to specific commands (e.g. " + example + ") if possible"
			}
		}
	}
	return "", ""
}

// isDevinAgentProfile reports whether path is a Devin CLI custom subagent
// profile under .devin/agents. There allowed-tools is the opposite of a grant:
// "On a subagent profile, allowed-tools restricts the tool set; on a skill, it
// does not" (Devin CLI skill docs), so reporting it as broad would be wrong.
func isDevinAgentProfile(path string) bool {
	return strings.Contains(filepath.ToSlash(path), "/.devin/agents/") || strings.HasPrefix(filepath.ToSlash(path), ".devin/agents/")
}
