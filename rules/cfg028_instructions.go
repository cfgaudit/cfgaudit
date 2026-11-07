// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

var (
	// widenActionRe is an imperative that writes: at the start of a line or
	// sentence, or after a word that opens a step.
	widenActionRe = regexp.MustCompile(`(?i)(?:^|[.;:!?]\s+|\n\s*|\b(?:then|first|next|now|please|and),?\s+)(?:[-*+]\s+|\d+[.)]\s+)?(?:\*{1,2})?(edit|update|change|modify|set|write|add|append|patch|overwrite|insert)\s`)
	// widenNegatedRe ends a text that takes the action away from the agent.
	widenNegatedRe = regexp.MustCompile(`(?i)(?:\b(?:do\s+not|don'?t|don’t|never|must\s+not|should\s+not|ask\s+the\s+user\s+to|tell\s+the\s+user\s+to|the\s+user\s+(?:can|should|must|may))\s+(?:\w+\s+){0,2})$`)
	// widenTargetRe is a settings file of an agent or editor, by name or path.
	widenTargetRe = regexp.MustCompile(trustFile + `|(?i:\b(?:agent|editor|vs\s*code|vscode|cursor|claude(?:\s+code)?|copilot|kilo(?:\s+code)?|cline|roo(?:\s+code)?|codex|gemini)(?:['’]s)?\s+(?:\w+\s+)?(?:settings|config(?:uration)?|permissions)\b)`)
	// widenKeyRe is a key that decides what runs without asking.
	widenKeyRe = regexp.MustCompile(`(?i)\b(?:allowedCommands|deniedCommands|permissions\.allow|autoApprove|alwaysAllow|allowed_commands|bypassPermissions)\b`)
)

// widensOwnPermissions returns the offset of the action in a paragraph telling
// the agent to widen its own permissions: an imperative write, a settings target
// and a permission key together (#1411). Naming a key is what setup guides do,
// so none of the three is enough alone.
func widensOwnPermissions(text string) (int, bool) {
	if !widenKeyRe.MatchString(text) || !widenTargetRe.MatchString(text) {
		return 0, false
	}
	for _, m := range widenActionRe.FindAllStringSubmatchIndex(text, -1) {
		if !widenNegatedRe.MatchString(text[:m[2]]) {
			return m[2], true
		}
	}
	return 0, false
}

// instructionFindings reports a prose instruction to widen the agent's own
// permissions. The message never quotes the paragraph, so no value of a setting
// ends up in a report.
func (r *cfg028) instructionFindings(t *Target) []finding.Finding {
	var findings []finding.Finding
	for _, src := range t.instructionSources(r.ID()) {
		for _, p := range instructionParagraphs(src.Content) {
			at, ok := widensOwnPermissions(p.text)
			if !ok {
				continue
			}
			line := p.startLine + strings.Count(p.text[:at], "\n")
			findings = append(findings, finding.Finding{
				RuleID:   "CFG028",
				Severity: finding.Error,
				File:     src.File,
				Line:     line,
				Message:  src.Name + " line " + strconv.Itoa(line) + " tells the agent to widen its own permissions by writing a settings file — a repository must not grant itself what the user would have to approve. Remove it, or ask the user to make the change",
			})
		}
	}
	return findings
}
