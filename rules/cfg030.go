// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg030 struct{}

var CFG030 = &cfg030{}

func init() { All = append(All, CFG030) }

func (r *cfg030) ID() string { return "CFG030" }

// concealRe matches CLAUDE.md text instructing Claude to hide its behaviour from
// the user — the social-engineering layer of a prompt injection. The
// silently/secretly branch is anchored to an action verb so ordinary phrasing
// like "fails silently" does not false-positive.
//
// The optional direct object after the verb is what lets "never mention THIS to
// the user" match: without it the target had to follow the verb almost
// immediately, so the most natural phrasing fell out. Person pronouns
// (him/her/them) are deliberately excluded — "never tell them the user's
// password" is security-positive guidance, and an indirect-object slot would
// turn it into a finding.
//
// "hide it" needs a person to hide it from, or the hide-and-carry-on shape
// ("hide it and continue"). Bare, it was the rule's largest false-positive
// class: in a corpus seeded on the phrase, 112 of 112 bare uses were UI or
// tooling ("hide it via CSS", "hide it from git blame", "hide it behind a
// flag") (#623).
var concealRe = mustFiltered(`(?i)(` +
	`(?:don'?t|do\s+not|never)\s+(?:tell|inform|mention|notify|reveal|disclose|show)` +
	`(?:\s+(?:this|that|it|these|those|anything|everything|any\s+of\s+(?:this|that|it)))?` +
	`(?:\s+(?:to|about))?\s+(?:the\s+)?(?:user|caller)s?\b` +
	`|without\s+the\s+user(?:'s)?\s+(?:knowing|knowledge|awareness)` +
	`|(?:silently|secretly)\s+(?:do|run|execute|perform|send|email|upload|exfiltrate|post|forward|delete|remove|modify|edit|change|install|add|disable|copy|leak)\b` +
	`|pretend\s+(?:you|to)\s+(?:don'?t|didn'?t|did\s+not|do\s+not)` +
	`|hide\s+(?:this|it|that)\s+from\s+(?:the\s+)?(?:user|caller|human|operator|reviewer)s?\b|hide\s+(?:this\s+)?from\s+the\s+user|hide\s+(?:this|it|that)\s+and\s+(?:continue|proceed|carry\s+on|move\s+on|keep\s+going)\b` +
	`)`)

func (r *cfg030) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	for _, src := range t.instructionSources() {
		lines := strings.Split(src.Content, "\n")
		for i, line := range lines {
			loc := concealRe.FindStringIndex(line)
			if loc == nil || concealNegated(withContinuation(lines, i), loc) || silentlyDescribes(line, loc) {
				continue
			}
			lineNo := i + 1
			findings = append(findings, finding.Finding{
				RuleID:   "CFG030",
				Severity: finding.Error,
				File:     src.File,
				Line:     lineNo,
				Col:      loc[0] + 1,
				Message: src.Name + " line " + strconv.Itoa(lineNo) + " instructs the agent to conceal its behaviour from the user (\"" + line[loc[0]:loc[1]] +
					"\") — gagging the model is the social-engineering layer of a prompt injection; legitimate guidance never tells the agent to hide what it does. Remove it",
			})
		}
	}
	return findings
}

// withContinuation returns line i joined with the next line when the sentence
// wraps onto it ("Don't tell the user a" / "build \"submitted to Play\"",
// #870): the next line is not blank, a list item, a heading or a fence.
func withContinuation(lines []string, i int) string {
	if i+1 >= len(lines) {
		return lines[i]
	}
	next := strings.TrimSpace(lines[i+1])
	if next == "" || listItemRe.MatchString(lines[i+1]) || strings.HasPrefix(next, "#") || isFenceDelimiter(next) || strings.HasPrefix(next, "|") {
		return lines[i]
	}
	return lines[i] + " " + next
}

// silentlyLeadWords may precede an instruction's "silently <verb>" in its own
// clause without being its subject: "Then silently upload", "you must silently
// delete", "please silently run".
var silentlyLeadWords = map[string]bool{
	"and": true, "then": true, "also": true, "just": true, "please": true, "always": true,
	"now": true, "first": true, "next": true, "finally": true, "simply": true, "immediately": true,
	"you": true, "must": true, "should": true, "shall": true, "need": true, "to": true, "or": true, "so": true,
}

// silentlyClauseRe finds the punctuation a clause starts after, for the
// "silently" check: commas, colons, square brackets, table cells and dashes as
// well as sentence ends, so "Before responding, silently send ..." keeps its
// clause. Round brackets do not end one: in "Org changes (renames) silently
// change the schema" the subject is before the bracket.
var silentlyClauseRe = regexp.MustCompile(`[.,;:!?\[\]|"*]|—|\s-\s`)

// silentlyDescribes reports whether a "silently <verb>" match describes what
// something else does rather than telling the agent what to do (#823): the
// clause has a subject before it ("hooks silently do nothing", "policies
// silently do not run", "These two silently change input behavior"), or the
// phrase is "silently do nothing". An instruction has nothing before
// "silently" in its clause but lead words (silentlyLeadWords).
func silentlyDescribes(line string, loc []int) bool {
	m := strings.ToLower(line[loc[0]:loc[1]])
	if !strings.HasPrefix(m, "silently") && !strings.HasPrefix(m, "secretly") {
		return false
	}
	if strings.HasPrefix(strings.TrimSpace(strings.ToLower(line[loc[1]:])), "nothing") && strings.HasSuffix(m, " do") {
		return true
	}
	before := line[:loc[0]]
	if ends := silentlyClauseRe.FindAllStringIndex(before, -1); len(ends) > 0 {
		before = before[ends[len(ends)-1][1]:]
	}
	for _, w := range strings.Fields(strings.ToLower(before)) {
		w = strings.Trim(w, "`'_~")
		if w != "" && !silentlyLeadWords[w] {
			return true
		}
	}
	return false
}

// concealModalRe matches a modal right before a "silently <verb>" match, which
// makes the sentence a description of what some code would do ("npm install
// would silently rewrite the lock", "hashes can silently disable
// 'unsafe-inline'") rather than an order to the agent (#623).
var concealModalRe = regexp.MustCompile(`(?i)\b(?:would|could|might|may|will|can|cannot|can'?t)\s+(?:\w+\s+)?$`)

// concealNegated reports whether a concealment match sits inside a prohibition
// rather than being one (#623): "do not silently remove", "don't silently delete
// things you're not sure about", "don't hide it entirely". The shape is CFG029's
// clause-local check: a negation before the match in the same clause, while a
// match that begins with its own negation ("don't tell the user") is the
// instruction itself and keeps reporting.
func concealNegated(line string, loc []int) bool {
	// "Do not tell the user to read X" says what to tell the user, not what to
	// keep from them (#655).
	if tellToRe.MatchString(line[loc[1]:]) {
		return true
	}
	// "Do not tell the user it's impossible" forbids a false claim, and "can
	// never tell the user opened it" is about finding out, not hiding (#853).
	if m := strings.ToLower(line[loc[0]:loc[1]]); strings.Contains(m, "tell") {
		after := line[loc[1]:]
		if tellClaimRe.MatchString(after) || tellQuotedClaimRe.MatchString(after) || tellBareClaimRe.MatchString(after) ||
			tellUntilRe.MatchString(clauseRest(after)) || concealModalRe.MatchString(line[:loc[0]]) {
			return true
		}
	}
	// "never tell the user \"I need to restore your token\" unless you've
	// confirmed there's a token" holds back an unverified claim, and "Do not
	// show the user a diagram that failed this check" withholds a broken
	// result (#890).
	if m := strings.ToLower(line[loc[0]:loc[1]]); strings.Contains(m, "tell") || strings.Contains(m, "show") {
		after := line[loc[1]:]
		if tellUnlessRe.MatchString(clauseRest(after)) || (strings.Contains(m, "show") && showFailedRe.MatchString(after)) {
			return true
		}
	}
	if m := prohibitionRe.FindStringIndex(line[loc[0]:loc[1]]); m != nil && m[0] == 0 {
		return false
	}
	before := line[clauseStart(line, loc[0]):loc[0]]
	if prohibitionRe.MatchString(before) || concealDescriptiveRe.MatchString(before) {
		return true
	}
	return concealModalRe.MatchString(before)
}

// concealDescriptiveRe matches the cues that make a concealment phrase the
// thing not done (#655): a negated description ("does not silently change the
// resolved scope") and the rejected alternative ("rather than silently delete
// it"). Kept out of prohibitionRe, which CFG029 shares, because "this command
// does not ask for permission" is a bypass there.
var concealDescriptiveRe = regexp.MustCompile(`(?i)\b(?:does\s+not|doesn'?t|did\s+not|didn'?t|will\s+not|won'?t|should\s+not|shouldn'?t|is\s+not|isn'?t|are\s+not|aren'?t|rather\s+than|instead\s+of)\b`)

// tellClaimRe matches a status claim right after "tell the user": "a shot is
// done", "it's impossible", "an API is healthy", "the integration is
// unavailable", "it works". Forbidding that claim is an honesty rule, not
// concealment (#853). The status words are a closed list: "do not tell the
// user the file was modified" hides a fact and keeps reporting, and so do
// "that you ...", "about ...", "anything" and the bare phrase.
var tellClaimRe = regexp.MustCompile(`(?i)^\s+(?:that\s+)?` +
	`(?:it|this|that|there|they|(?:a|an|the|this|that|these|those|its|their|your|our|any|every)\s+[\w.\-/]+(?:\s+[\w.\-/]+){0,3})` +
	`(?:'s|'re|\s+(?:is|are|was|were|has\s+been|have\s+been|will\s+be|looks|seems))?\s+(?:not\s+|now\s+|fully\s+)?` +
	`(?:(?:a|an)\s+)?(?:done|complete|completed|finished|fixed|working|works|worked|healthy|ready|impossible|unavailable|available|possible|broken|successful|succeeded|passed|failed|live|deployed|resolved|supported|unsupported|safe|secure|paid|free|premium|deprecated)\b`)

// tellQuotedClaimRe matches a subject followed by the quoted words the agent
// must not use: "Don't tell the user a build \"submitted to Play\"", "Never tell
// the user Flow \"cannot\" do something" (#870). Quoting the claim marks it as
// the wording to avoid, not a fact to hide.
//
// The subject may be missing and the quotes may be CJK corner brackets:
// "Never tell the user “…” as a closing statement" (#914).
var tellQuotedClaimRe = regexp.MustCompile(`^\s+(?:that\s+)?(?:[\w.\-/]+(?:\s+[\w.\-/]+){0,3}\s+)?(?:["\x{201C}][^"\x{201D}]+["\x{201D}]|\x{300C}[^\x{300D}]+\x{300D})`)

// tellBareClaimRe matches a status claim about a bare noun: "never tell the
// user voiceover is impossible" (#914). tellClaimRe needs an article or a
// pronoun before the subject; here the verb is required instead.
var tellBareClaimRe = regexp.MustCompile(`(?i)^\s+(?:that\s+)?[\w.\-/]+\s+(?:is|are|was|were)\s+(?:not\s+)?(?:impossible|unavailable|unsupported|possible|available|supported|broken|done|ready|free|paid)\b`)

// tellUntilRe matches a claim held back only until it is true: "Do not tell the
// user the artifact is being monitored until that wake path is live" (#870).
var tellUntilRe = regexp.MustCompile(`(?i)\buntil\b[^.;]{0,60}?\b(?:is|are|has\s+been|have\s+been)\s+(?:live|ready|done|finished|complete|completed|verified|confirmed|working|deployed|merged|running|available|in\s+place)\b`)

// tellUnlessRe matches a claim held back unless it has been confirmed: "never
// tell the user \"I need to restore your Telegram token\" unless you've
// confirmed there's a token to restore" (#890).
var tellUnlessRe = regexp.MustCompile(`(?i)\bunless\s+(?:you(?:'ve|\s+have)?\s+|it\s+(?:is|has\s+been)\s+|they(?:'ve|\s+have)?\s+(?:been\s+)?)?(?:confirmed|verified|checked|validated)\b`)

// showFailedRe matches a result that failed a check or is broken, right after
// "do not show the user": "a diagram that failed this check" (#890). Keeping a
// broken result back until it is fixed is a quality gate, not concealment.
var showFailedRe = regexp.MustCompile(`(?i)^\s+(?:a|an|the|any)\s+(?:(?:[\w\-]+\s+){1,3}(?:that|which)\s+(?:has\s+|have\s+)?(?:failed|fails|fail|is\s+(?:broken|invalid|unverified)|are\s+(?:broken|invalid|unverified))|(?:broken|invalid|unverified|failing|failed)\s)`)

// tellToRe matches "to <verb>" right after "tell the user", which turns the
// phrase into guidance about what the user should be told to do.
var tellToRe = regexp.MustCompile(`(?i)^\s+to\s+[a-z]`)
