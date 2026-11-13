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
//
// The imperative must share its sentence with the key or with a permission
// entry it adds (`Agent(*)`, `Bash(npm test:*)`), and the key and target
// must be in the same list item, table row or paragraph (#1673). Read over a whole
// paragraph, a "set `--tools`" in one sentence and a descriptive
// "`bypassPermissions`" in the next, or the rows of a table, made one
// instruction; "Add this entry to `permissions.allow`" after a sentence that
// names `.claude/settings.local.json` still is one. A bold label of several
// words ("**Write tasks need a grant**") is an imperative only when the target
// is in its sentence too ("**Update permissions** — if the repo has
// `.claude/settings.json`, add …").
func widensOwnPermissions(text string) (int, bool) {
	if !widenKeyRe.MatchString(text) || !widenTargetRe.MatchString(text) {
		return 0, false
	}
	for _, b := range widenBlocks(text) {
		block := text[b[0]:b[1]]
		if !widenKeyRe.MatchString(block) || !widenTargetRe.MatchString(block) {
			continue
		}
		for _, u := range widenSentences(block) {
			sentence := block[u[0]:u[1]]
			if !widenKeyRe.MatchString(sentence) && !permissionEntryRe.MatchString(sentence) {
				continue
			}
			for _, m := range widenActionRe.FindAllStringSubmatchIndex(sentence, -1) {
				if widenNegatedRe.MatchString(sentence[:m[2]]) {
					continue
				}
				if boldLabelAt(sentence, m[2]) && !widenTargetRe.MatchString(sentence) {
					continue
				}
				return b[0] + u[0] + m[2], true
			}
		}
	}
	return 0, false
}

// permissionEntryRe is a permission rule in code formatting, the thing an
// instruction adds to an allow list: `Agent(*)`, `"Bash(npm test:*)"`,
// `Skill(x:y)`, `mcp__github__create_issue`.
var permissionEntryRe = regexp.MustCompile("`\"?(?:(?:Bash|Read|Write|Edit|MultiEdit|Agent|Task|Skill|WebFetch|WebSearch|Glob|Grep|NotebookEdit)\\([^`)]*\\)|mcp__[\\w-]+)\"?`")

// widenListItemRe starts a list item or a table row on a line.
var widenListItemRe = regexp.MustCompile(`^\s*(?:[-*+]\s|\d+[.)]\s|\|)`)

// widenBlocks splits a paragraph into list items, table rows and the text
// between them, as [start, end) offsets. A list item runs to the next item
// or row; a table row ends at its line.
func widenBlocks(text string) [][2]int {
	var blocks [][2]int
	start := 0
	tableRow := false
	for lineStart := 0; lineStart < len(text); {
		nl := strings.IndexByte(text[lineStart:], '\n')
		lineEnd := len(text)
		if nl >= 0 {
			lineEnd = lineStart + nl + 1
		}
		line := text[lineStart:lineEnd]
		if widenListItemRe.MatchString(line) || tableRow {
			if lineStart > start {
				blocks = append(blocks, [2]int{start, lineStart})
			}
			start = lineStart
		}
		tableRow = strings.HasPrefix(strings.TrimLeft(line, " \t"), "|")
		lineStart = lineEnd
	}
	if len(text) > start {
		blocks = append(blocks, [2]int{start, len(text)})
	}
	return blocks
}

// widenSentences splits a block into sentences, as [start, end) offsets with
// leading white space and a list or table marker left out. A sentence ends at
// ., ! or ? followed by white space, outside a code span and not after an
// abbreviation.
func widenSentences(block string) [][2]int {
	var out [][2]int
	start, inCode := 0, false
	if m := widenListItemRe.FindString(block); m != "" {
		start = len(m) - 1
		if strings.HasSuffix(m, "|") {
			start = len(m)
		}
	}
	emit := func(end int) {
		s := start
		for s < end && strings.ContainsRune(" \t\n", rune(block[s])) {
			s++
		}
		if end > s {
			out = append(out, [2]int{s, end})
		}
		start = end
	}
	for i := start; i < len(block); i++ {
		switch c := block[i]; {
		case c == '`':
			inCode = !inCode
		case c == '\n':
			inCode = false
		case !inCode && (c == '.' || c == '!' || c == '?'):
			// Closing emphasis or quotes may follow: "**Write tasks need a
			// grant.** Pass …".
			j := i + 1
			for j < len(block) && strings.ContainsRune("*_\"')", rune(block[j])) {
				j++
			}
			if j >= len(block) || !strings.ContainsRune(" \t\n", rune(block[j])) {
				continue
			}
			if c == '.' && abbreviationBefore(block[:i]) {
				continue
			}
			emit(j)
			i = j - 1
		}
	}
	emit(len(block))
	return out
}

// widenAbbrevRe is a word whose period does not end a sentence: e.g, i.e,
// etc, vs, cf, a version number (v1.2).
var widenAbbrevRe = regexp.MustCompile(`(?i)(?:^|[\s(])(?:e\.g|i\.e|etc|vs|cf|incl|approx|v?\d+(?:\.\d+)*)$`)

func abbreviationBefore(text string) bool {
	return widenAbbrevRe.MatchString(text)
}

// boldLabelAt reports a verb that opens a bold label of more than one word:
// "**Write tasks need a grant**", "**Write / build** (scaffold, …)". A
// bold verb on its own ("**Write** `x` into …") is still an instruction.
func boldLabelAt(unit string, verb int) bool {
	if !strings.HasSuffix(unit[:verb], "**") {
		return false
	}
	end := strings.Index(unit[verb:], "**")
	if end < 0 {
		return false
	}
	return len(strings.Fields(unit[verb:verb+end])) > 1
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
