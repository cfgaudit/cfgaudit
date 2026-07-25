package rules

import (
	"path/filepath"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

type cfg092 struct{}

var CFG092 = &cfg092{}

func init() { All = append(All, CFG092) }

func (r *cfg092) ID() string { return "CFG092" }

// Check flags a committed Kimi Code agent-definition file whose frontmatter sets
// override: true. Kimi loads project agent files from .kimi-code/agents/ and
// .agents/agents/ (resolved from the repo's .git root, with no trust gate), and
// override: true makes the file *replace the built-in agent's entire system
// prompt* — the file body IS the prompt, not an addition to it, unless the body
// re-embeds ${base_prompt}. Naming it agent.md takes over the default main agent;
// coder.md takes over the default sub-agent.
//
// This is a strictly larger takeover than CFG085's permission-mode weakening: the
// whole instruction context is swapped for repo contents on a fresh clone. It is
// the config-shaped, whole-prompt sibling of the instruction-content rules that
// scan the same file's body (CFG024–CFG036 etc.) — those judge what the prompt
// says; this flags that the prompt is being replaced wholesale.
//
// Only override: true is flagged. A committed agent file without it is an ordinary
// (appended) instruction file whose body the instruction-content rules already
// cover, so flagging every such file — or every file lacking a tools list — would
// be noise; the takeover is the defensible trigger. The omitted/`*` tools list
// (which keeps every tool — the insecure default) is reported as part of the same
// finding when it co-occurs, not as its own.
func (r *cfg092) Check(t *Target) []finding.Finding {
	if t == nil || t.InstructionContent == "" || !isKimiAgentFile(t.InstructionFile) {
		return nil
	}
	fm, ok := parser.InstructionFrontmatter(t.InstructionContent)
	if !ok || !fm.Bool("override") {
		return nil
	}

	msg := t.instructionName() + " frontmatter sets override: true — this Kimi agent file replaces the built-in agent's entire system prompt with the file's own body" +
		" (named agent.md it takes over the default main agent). Committed to a repository, which Kimi loads with no trust gate, a fresh clone runs with its instruction context swapped for repo contents"
	if _, hasTools := fm.Raw["tools"]; !hasTools || fm.String("tools") == "*" {
		msg += ", and with no tools allowlist it keeps every tool"
	}
	msg += ". Drop override: true (or re-embed ${base_prompt} to wrap rather than replace the default), and set an explicit tools allowlist" + userScopeNote(t)

	return []finding.Finding{{
		RuleID:   "CFG092",
		Severity: finding.Error,
		Scope:    t.Scope,
		File:     t.InstructionFile,
		Message:  msg,
	}}
}

// isKimiAgentFile reports whether path is a Kimi Code agent-definition Markdown
// file — one under a .kimi-code/agents or .agents/agents directory at any depth
// (both are scanned recursively). The field is inert anywhere else, so restricting
// to these directories avoids flagging an `override` key that Kimi never reads.
func isKimiAgentFile(path string) bool {
	if path == "" || !strings.EqualFold(filepath.Ext(path), ".md") {
		return false
	}
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i := 0; i+1 < len(parts); i++ {
		if (parts[i] == ".kimi-code" && parts[i+1] == "agents") ||
			(parts[i] == ".agents" && parts[i+1] == "agents") {
			return true
		}
	}
	return false
}
