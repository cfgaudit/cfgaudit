package rules

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg029 struct{}

var CFG029 = &cfg029{}

func init() { All = append(All, CFG029) }

func (r *cfg029) ID() string { return "CFG029" }

// permissionBypassRe matches text instructing Claude to auto-approve or skip
// confirmation — disabling the permission system via system context, the
// natural-language equivalent of defaultMode: bypassPermissions (CFG004).
//
// Two groups. The first matches anywhere (unambiguous bypass language). The
// second covers ask/prompt-based forms, which must carry a permission/run object
// — so "never ask for approval" / "without asking before running" match, while
// the benign "never ask the user for API keys" / "don't ask clarifying
// questions" (UX / good practice) do not.
//
// The approve-class accepts the adverb in either position. Leading is
// unambiguous ("automatically approve …"). Trailing is not — "approve any
// pending PR automatically" is ordinary review workflow, not a permission
// bypass — so the postfix form additionally requires a permission-specific
// object between the verb and the adverb.
var permissionBypassRe = regexp.MustCompile(`(?i)(` +
	`(?:always|automatically)\s+approve` +
	`|auto-?approve` +
	`|approve\b[^.\n]{0,30}?\b(?:permission|approval|confirmation|prompt)s?\b[^.\n]{0,25}?\b(?:automatically|without\s+asking|by\s+default)` +
	`|bypass\s+(?:permission|confirmation|approval)` +
	`|skip\s+(?:confirm(?:ation)?|approval|the\s+prompt)` +
	`|without\s+(?:confirm(?:ation)?|approval|prompt(?:ing)?)` +
	`|never\s+(?:prompt|confirm|require\s+approval)` +
	`|(?:without\s+asking|never\s+ask(?:ing)?|do\s+not\s+ask|don'?t\s+ask|do\s+not\s+prompt)\s+(?:the\s+user\s+)?(?:for\s+)?(?:permission|approval|confirmation|before\s+(?:running|executing|proceeding|making|applying|doing))` +
	`)`)

// prohibitionRe matches the cues that turn a line, or the line governing a list,
// into a prohibition. Kept separate from the bypass pattern because the two are
// asked different questions: this one is looked for *around* a match, never as
// one.
var prohibitionRe = regexp.MustCompile(`(?i)\b(never|do\s+not|don'?t|must\s+not|mustn'?t|may\s+not|cannot|can'?t|avoid|refuse\s+to|forbidden|prohibited|not\s+allowed|no\s+circumstances)\b`)

// listItemRe matches a markdown list item and captures its indentation, so the
// walk up to a list's governing line can tell a sibling from a parent.
var listItemRe = regexp.MustCompile(`^(\s*)(?:[-*+]|\d+[.)])\s+`)

// clauseStart returns the offset of the clause that ends at end: the text after
// the last sentence or clause break before it. A break is punctuation followed
// by whitespace, so a filename ("`.env` contents") does not split a line, while
// a real sentence boundary does.
//
// A colon is deliberately not a break. In these files a colon introduces a list
// or an enumeration that the words before it govern ("Never: push to main"), so
// cutting there would drop the very negation that is being looked for.
func clauseStart(line string, end int) int {
	start := 0
	for i := 0; i+1 < end && i+1 < len(line); i++ {
		if (line[i] == '.' || line[i] == ';' || line[i] == '!' || line[i] == '?') &&
			(line[i+1] == ' ' || line[i+1] == '\t') {
			start = i + 2
		}
	}
	return start
}

// negated reports whether the match at loc sits inside a prohibition rather than
// being one.
//
// Three shapes, in order:
//
//   - The match begins with a negation of its own ("don't ask permission",
//     "never prompt"). That IS the bypass instruction, phrased negatively, so it
//     is not negated by anything and keeps reporting. Checking this first is
//     what keeps the rule's main true positive alive.
//
//   - A negation precedes the match in the same clause ("Never auto-approve
//     destructive operations", "Do not install new packages without confirming
//     with the user"). The second one is the inverse of the finding: it demands
//     confirmation.
//
//   - The line is a list item whose governing line is a prohibition ("**Never
//     without explicit user request:**" above a list holding "Push to remote
//     without confirmation"). The negation is not on the line at all, which is
//     the shape a line-local check alone cannot see.
//
// Suppressing these is not an evasion route worth worrying about: the text that
// silences the rule is the same text the model reads, so a payload hidden under
// a fake "never do these" heading instructs the agent not to do it either.
func negated(lines []string, i int, loc []int) bool {
	line := lines[i]
	if m := prohibitionRe.FindStringIndex(line[loc[0]:loc[1]]); m != nil && m[0] == 0 {
		return false
	}
	if prohibitionRe.MatchString(line[clauseStart(line, loc[0]):loc[0]]) {
		return true
	}
	g := governingLine(lines, i)
	// Only the clause the list hangs off counts, for the same reason the line
	// check is clause-scoped: a long paragraph that ends in a colon can carry a
	// negation about something else entirely. Measured, that is not theoretical
	// -- "do **not** rely on a tool EXECUTE event ... Instead, implement approval
	// as a wrapper around the tool's `execute`:" introduces a to-do list, and
	// reading its "do not" as a prohibition header suppressed a real finding in
	// the list below it.
	return introducesList(g) && prohibitionRe.MatchString(g[clauseStart(g, len(g)):])
}

// introducesList reports whether a line is the kind that governs the list under
// it: a Markdown heading, or a line that ends in a colon.
//
// Requiring that shape is what keeps the list check from reading a negation that
// is about something else. Measured over 601 instruction files seeded on this
// rule's own phrases, dropping it suppressed a real finding ("read-only tools →
// auto-approve") because an unrelated paragraph above the list happened to say
// "do not rely on a tool EXECUTE event". The prohibition headers that matter in
// real files all have this shape: "Claude must not:", "**Never:**",
// "Forbidden:", "## DO NOT", "## Must Not".
func introducesList(line string) bool {
	t := strings.TrimSpace(line)
	if t == "" {
		return false
	}
	if strings.HasPrefix(t, "#") {
		return true
	}
	// Trailing emphasis and code markers sit outside the colon in real files
	// ("**Never:**"), so they are trimmed before the check.
	return strings.HasSuffix(strings.TrimRight(t, "*_`~ "), ":")
}

// governingLine returns the line a list item hangs under: the nearest line above
// it that is not a blank line and not a sibling or deeper list item. It returns
// "" for a line that is not a list item, and for a list whose governing line is
// further away than maxGoverningDistance, where attributing a heading to an item
// stops being justified.
func governingLine(lines []string, i int) string {
	const maxGoverningDistance = 20
	m := listItemRe.FindStringSubmatch(lines[i])
	if m == nil {
		return ""
	}
	indent := len(m[1])
	for j := i - 1; j >= 0 && i-j <= maxGoverningDistance; j-- {
		prev := lines[j]
		if strings.TrimSpace(prev) == "" {
			continue
		}
		if pm := listItemRe.FindStringSubmatch(prev); pm != nil {
			if len(pm[1]) < indent {
				return prev // the parent item of a nested list
			}
			continue // a sibling
		}
		return prev
	}
	return ""
}

func (r *cfg029) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	for _, src := range t.instructionSources() {
		lines := strings.Split(src.Content, "\n")
		for i, line := range lines {
			loc := permissionBypassRe.FindStringIndex(line)
			if loc == nil {
				continue
			}
			if negated(lines, i, loc) {
				continue
			}
			lineNo := i + 1
			findings = append(findings, finding.Finding{
				RuleID:   "CFG029",
				Severity: finding.Error,
				File:     src.File,
				Line:     lineNo,
				Col:      loc[0] + 1,
				Message: src.Name + " line " + strconv.Itoa(lineNo) + " instructs the agent to bypass permission prompts (\"" + line[loc[0]:loc[1]] +
					"\") — this disables the permission system via system-context text, equivalent to defaultMode: bypassPermissions (CFG004). Remove it",
			})
		}
	}
	return findings
}
