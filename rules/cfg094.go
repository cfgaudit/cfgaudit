package rules

import (
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg094 struct{}

var CFG094 = &cfg094{}

func init() { All = append(All, CFG094) }

func (r *cfg094) ID() string { return "CFG094" }

// Check flags committed `autoRun` instructions in a Cursor
// `.cursor/permissions.json`.
//
// `autoRun.allow_instructions` and `block_instructions` are natural-language
// sentences fed to the classifier that decides, in Auto-review mode, whether a
// tool call runs without asking. That makes the gatekeeper itself
// repo-controlled: the text arrives from the repository and steers an LLM's
// approval decision. It is the CFG079 threat model (tuning the auto-approval
// classifier from committed config) in Cursor's file, with the difference that
// Cursor's version is prose rather than match rules, so there is no syntax to
// bound what a sentence can talk the classifier into.
//
// Only `allow_instructions` is flagged. A `block_instructions` entry pushes the
// classifier toward *asking*, which is the safe direction; flagging a repo for
// adding caution would be noise. They are decoded and mentioned in the message
// only when they exist alongside an allow instruction.
//
// **Severity is warn, not error.** Two reasons, both from Cursor's own docs.
// The instructions are consulted only in Auto-review mode, a narrower condition
// than CFG093's "any Run Mode". And Cursor states outright that "allowlists and
// autoRun instructions are best-effort convenience. They are not a security
// guarantee", so the classifier is not presented as the thing standing between
// the repo and execution. The finding is that a repo is steering a teammate's
// approval decisions at all, which a reviewer should see; claiming a specific
// bypass would require knowing how the classifier weighs the sentence, which is
// not knowable from the file.
func (r *cfg094) Check(t *Target) []finding.Finding {
	if t == nil || t.CursorPermissions == nil || t.Scope == finding.ScopeUser {
		return nil
	}
	ar := t.CursorPermissions.AutoRun
	if ar == nil {
		return nil
	}
	var allow []string
	for _, s := range ar.AllowInstructions {
		if s = strings.TrimSpace(s); s != "" {
			allow = append(allow, s)
		}
	}
	if len(allow) == 0 {
		return nil
	}

	msg := "committed .cursor/permissions.json autoRun.allow_instructions steers Cursor's auto-approval classifier with repo-supplied prose (" +
		quoteFirst(allow) + ") — in Auto-review mode this text is what decides whether a tool call runs without asking, so the repository is tuning a teammate's approval gate in natural language, with no syntax bounding what it can argue for. Move the intent into an explicit terminalAllowlist/mcpAllowlist entry, which states exactly what it grants"
	if len(ar.BlockInstructions) > 0 {
		msg += " (the accompanying block_instructions are not the concern: they push the classifier toward asking)"
	}
	return []finding.Finding{{
		RuleID:   "CFG094",
		Severity: finding.Warn,
		Scope:    t.Scope,
		File:     t.CursorPermissionsFile,
		Message:  msg,
	}}
}

// quoteFirst renders the first instruction, truncated, plus a count of the rest,
// so a long prose block does not swamp the finding line.
func quoteFirst(entries []string) string {
	first := entries[0]
	const max = 80
	if len(first) > max {
		first = strings.TrimSpace(first[:max]) + "…"
	}
	out := "\"" + first + "\""
	switch n := len(entries) - 1; {
	case n == 1:
		out += " and 1 more"
	case n > 1:
		out += " and " + strconv.Itoa(n) + " more"
	}
	return out
}
