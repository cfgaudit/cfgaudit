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
var concealRe = regexp.MustCompile(`(?i)(` +
	`(?:don'?t|do\s+not|never)\s+(?:tell|inform|mention|notify|reveal|disclose|show)(?:\s+(?:to|about))?\s+(?:the\s+)?(?:user|caller)` +
	`|without\s+the\s+user(?:'s)?\s+(?:knowing|knowledge|awareness)` +
	`|(?:silently|secretly)\s+(?:do|run|execute|perform|send|email|upload|exfiltrate|post|forward|delete|remove|modify|edit|change|install|add|disable|copy|leak)` +
	`|pretend\s+(?:you|to)\s+(?:don'?t|didn'?t|did\s+not|do\s+not)` +
	`|hide\s+(?:this|it)\b|hide\s+(?:this\s+)?from\s+the\s+user` +
	`)`)

func (r *cfg030) Check(t *Target) []finding.Finding {
	if t == nil || t.ClaudeMDContent == "" {
		return nil
	}
	var findings []finding.Finding
	for i, line := range strings.Split(t.ClaudeMDContent, "\n") {
		loc := concealRe.FindStringIndex(line)
		if loc == nil {
			continue
		}
		lineNo := i + 1
		findings = append(findings, finding.Finding{
			RuleID:   "CFG030",
			Severity: finding.Error,
			File:     t.ClaudeMDFile,
			Line:     lineNo,
			Col:      loc[0] + 1,
			Message: "CLAUDE.md line " + strconv.Itoa(lineNo) + " instructs Claude to conceal its behaviour from the user (\"" + line[loc[0]:loc[1]] +
				"\") — gagging the model is the social-engineering layer of a prompt injection; legitimate guidance never tells Claude to hide what it does. Remove it",
		})
	}
	return findings
}
