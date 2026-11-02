// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

type cfg051 struct{}

var CFG051 = &cfg051{}

// shellWildcardGrantRe matches a Bash or Exec scope made only of wildcards, on
// an entry lowercased with its whitespace removed. On Claude Code 2.1.316
// Bash( * ), Bash(**) and Bash(* *) allow any command. Bash(* * *) did not, and
// is reported anyway, as it was before scalar lists were split outside
// parentheses. A : is not a wildcard here: Bash(*:*) and Bash(:*) did not allow
// any command.
var shellWildcardGrantRe = regexp.MustCompile(`^(?:bash|exec)\(\*+\)$`)

func init() { All = append(All, CFG051) }

func (r *cfg051) ID() string { return "CFG051" }

// Check flags a model-facing instruction file (skill SKILL.md, slash command, or
// subagent) whose YAML frontmatter grants overly broad tool access via
// allowed-tools. A committed command/skill that grants unrestricted shell or all
// tools lets it run anything when invoked — the frontmatter analogue of the
// permission-breadth rules (CFG002/CFG006). A grant cancelled by disallowed-tools
// is not flagged.
func (r *cfg051) Check(t *Target) []finding.Finding {
	if t == nil || t.InstructionContent == "" || isDevinAgentProfile(t.InstructionFile) || isGeminiSkill(t.InstructionFile) {
		return nil
	}
	root := skillRootKind(t.InstructionFile)
	if root == rootIgnoresField {
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
	// Unlike StringList, malformed denies must not add entries that cancel findings.
	disallowed := append(fm.DenyList("disallowed-tools"), fm.DenyList("disallowedTools")...)

	sev, what := analyzeAllowedTools(allowed, disallowed)
	if what == "" {
		return nil
	}
	switch {
	case root == rootUnmeasured:
		sev = finding.Info
		what += " (Claude Code does not read this skill root, and Copilot CLI 1.0.95 and OpenCode 1.18.18 do not treat allowed-tools as a grant; whether Codex or Cursor do is not measured)"
	case sev == finding.Warn && !grantsClaudeShell(allowed):
		// Claude Code matches tool names case-sensitively: measured on 2.1.316,
		// allowed-tools: bash let no Bash call through, Bash did (#1196).
		sev = finding.Info
		what = "names a shell tool Claude Code does not have (\"" + strings.Join(allowed, ", ") + "\"), so it grants nothing: Claude Code matches tool names case-sensitively and the tool is Bash"
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
		// compact is what shellWildcardGrantRe matches.
		compact := strings.Join(strings.Fields(low), "")
		switch {
		case tool == "*" || low == "all" || low == "full":
			if !cancelled(tool) {
				return finding.Error, "grants all tools (\"" + tool + "\") — unrestricted tool access"
			}
		// "exec" is Devin CLI's command tool (#644): its skill docs list the tool
		// names read, edit, grep, glob and exec, and say allowed-tools entries
		// are "auto-approved (no permission prompt) while the skill runs", so a
		// bare exec is unrestricted shell. A wildcard-only "exec(*)" is the same
		// grant.
		case low == "bash" || shellWildcardGrantRe.MatchString(compact) || low == "shell" || low == "execute" || low == "exec":
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

// The skill roots CFG051 distinguishes (#1196). Measured with a skill that
// runs `touch` under allowed-tools: Bash, against a baseline without it:
// Claude Code 2.1.316 runs it; Copilot CLI 1.0.95 (.github/skills,
// .agents/skills, .claude/skills, also with "shell" and "shell(touch)") and
// OpenCode 1.18.18 (.agents/skills, .opencode/skills, .claude/skills, with
// bash set to ask) still ask. Codex and Cursor could not be measured.
const (
	rootClaude = iota
	rootIgnoresField
	rootUnmeasured
)

// skillRootKind classifies the skill root of path: read only by agents that
// ignore allowed-tools, read by agents that were not measured, or a root
// Claude Code reads (the default, which covers .claude/ and plugins).
func skillRootKind(path string) int {
	p := strings.ReplaceAll(path, `\`, "/")
	switch {
	case strings.Contains(p, ".github/skills/"), strings.Contains(p, ".opencode/skill/"), strings.Contains(p, ".opencode/skills/"):
		return rootIgnoresField
	case strings.Contains(p, ".agents/skills/"), strings.Contains(p, ".codex/"), strings.Contains(p, ".cursor/skills/"):
		return rootUnmeasured
	}
	return rootClaude
}

// grantsClaudeShell reports whether an allowed-tools list names Claude Code's
// shell tool as Claude Code spells it, or Devin's exec, which CFG051 reads in
// the same files.
func grantsClaudeShell(allowed []string) bool {
	for _, raw := range allowed {
		tool := strings.TrimSpace(raw)
		low := strings.ToLower(tool)
		if strings.HasPrefix(tool, "Bash") || strings.HasPrefix(low, "exec") {
			return true
		}
	}
	return false
}

// isGeminiSkill reports whether path is a skill Gemini CLI loads from a
// .gemini/skills directory (project or user scope). Gemini CLI does not read
// allowed-tools, so the field grants nothing there (#1153). .qwen/skills is
// left in scope until Qwen Code is measured.
func isGeminiSkill(path string) bool {
	return strings.Contains(strings.ReplaceAll(path, `\`, "/"), ".gemini/skills/")
}
