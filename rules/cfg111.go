package rules

import (
	"fmt"
	"sort"
	"unicode"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg111 struct{}

// CFG111 reports a permission rule or hook matcher that carries an invisible
// character, which leaves it in the file and out of force.
var CFG111 = &cfg111{}

func init() { All = append(All, CFG111) }

func (r *cfg111) ID() string { return "CFG111" }

// Check reports invisible characters in permissions.allow / deny / ask entries
// and in hook matchers.
//
// Claude Code matches a rule by its exact text, so a hidden character makes the
// rule match nothing, and it says nothing about it. Measured on 2.1.288 with
// project settings allowing Bash(touch:*) and a scripted Bash tool call: a deny
// of Bash(touch:*) refused the command; the same deny with a zero-width space,
// a NUL, a right-to-left override or a soft hyphen inside it let the command
// run, and so did an ask rule with a zero-width space. The only log line is the
// rule being added. A PreToolUse hook whose matcher was "Ba\u200bsh" did not
// run for a Bash call that the plain matcher caught.
//
// So the rule reads as configured in review and in every editor, and does
// nothing: a deny or ask rule and a hook matcher are guardrails that silently
// stop guarding, which is error. A hidden character can only make an allow
// rule match less, never more, so it carries no risk and is info: the rule
// does not do what it says.
func (r *cfg111) Check(t *Target) []finding.Finding {
	if t == nil || t.Settings == nil {
		return nil
	}
	s := t.Settings
	var findings []finding.Finding
	report := func(sev finding.Severity, where, value, consequence string) {
		pos, ch, name, ok := firstHiddenRune(value)
		if !ok {
			return
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG111",
			Severity: sev,
			Scope:    t.Scope,
			File:     t.SettingsFile,
			Message: fmt.Sprintf("%s %q holds an invisible character U+%04X (%s) at position %d: Claude Code matches the text exactly, so %s, while the entry looks correct in every editor and review. Retype it without the character",
				where, visibleForm(value), ch, name, pos, consequence),
		})
	}

	if p := s.Permissions; p != nil {
		for _, rule := range p.Deny {
			report(finding.Error, "permissions.deny entry", rule, "this deny rule blocks nothing")
		}
		for _, rule := range p.Ask {
			report(finding.Error, "permissions.ask entry", rule, "this ask rule never prompts")
		}
		for _, rule := range p.Allow {
			report(finding.Info, "permissions.allow entry", rule, "this allow rule grants nothing")
		}
	}

	events := make([]string, 0, len(s.Hooks))
	for e := range s.Hooks {
		events = append(events, e)
	}
	sort.Strings(events)
	for _, event := range events {
		for _, group := range s.Hooks[event] {
			report(finding.Error, "hooks."+event+" matcher", group.Matcher, "the hooks under this matcher never run")
		}
	}
	return findings
}

// firstHiddenRune returns the 1-based rune position, the rune and a category
// name of the first invisible character in s.
//
// Invisible means a Unicode format character (category Cf: zero-width space,
// joiners, bidirectional controls, the Tags block, soft hyphen, BOM, word
// joiner), a control character (Cc, including NUL; line breaks and tab are
// exempt, see below), or one of the
// Hangul filler letters that render as blank. A permission rule or matcher has
// a use for none of them.
func firstHiddenRune(s string) (int, rune, string, bool) {
	runes := []rune(s)
	for i, r := range runes {
		pos := i + 1
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			// Claude Code writes these itself: a rule saved from "don't ask
			// again" on a multi-line command (a heredoc commit message, an inline
			// script) keeps its line breaks, and 26 of the 28 hits in the first
			// false-positive run were exactly that.
			continue
		case r == zwjRune && zwjJoinsEmoji(runes, i):
			continue // 👨\u200d💻 in a saved commit message, as in CFG024
		}
		if name, ok := suspiciousUnicode(r); ok {
			return pos, r, name, true
		}
		switch {
		case unicode.IsControl(r):
			return pos, r, "control character", true
		case unicode.Is(unicode.Cf, r):
			return pos, r, "invisible format character", true
		case r == 0x115F || r == 0x1160 || r == 0x3164 || r == 0xFFA0:
			return pos, r, "Hangul filler", true
		}
	}
	return 0, 0, "", false
}

// visibleForm renders s with every invisible character replaced by its
// U+XXXX escape, so the message shows where it is.
func visibleForm(s string) string {
	runes := []rune(s)
	out := make([]rune, 0, len(runes))
	for i, r := range runes {
		if hiddenAt(runes, i) {
			out = append(out, []rune(fmt.Sprintf("<U+%04X>", r))...)
			continue
		}
		out = append(out, r)
	}
	return string(out)
}

// hiddenAt reports whether runes[i] is a character firstHiddenRune reports,
// judged in context so an emoji joiner stays visible.
func hiddenAt(runes []rune, i int) bool {
	pos, _, _, ok := firstHiddenRune(string(runes[i:]))
	if !ok || pos != 1 {
		return false
	}
	return !(runes[i] == zwjRune && zwjJoinsEmoji(runes, i))
}
