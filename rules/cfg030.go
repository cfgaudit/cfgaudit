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
var concealRe = regexp.MustCompile(`(?i)(` +
	`(?:don'?t|do\s+not|never)\s+(?:tell|inform|mention|notify|reveal|disclose|show)` +
	`(?:\s+(?:this|that|it|these|those|anything|everything|any\s+of\s+(?:this|that|it)))?` +
	`(?:\s+(?:to|about))?\s+(?:the\s+)?(?:user|caller)` +
	`|without\s+the\s+user(?:'s)?\s+(?:knowing|knowledge|awareness)` +
	`|(?:silently|secretly)\s+(?:do|run|execute|perform|send|email|upload|exfiltrate|post|forward|delete|remove|modify|edit|change|install|add|disable|copy|leak)` +
	`|pretend\s+(?:you|to)\s+(?:don'?t|didn'?t|did\s+not|do\s+not)` +
	`|hide\s+(?:this|it)\b|hide\s+(?:this\s+)?from\s+the\s+user` +
	`)`)

func (r *cfg030) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	for _, src := range t.instructionSources() {
		for i, line := range strings.Split(src.Content, "\n") {
			loc := concealRe.FindStringIndex(line)
			if loc == nil {
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
