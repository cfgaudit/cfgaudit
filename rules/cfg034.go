package rules

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg034 struct{}

var CFG034 = &cfg034{}

func init() { All = append(All, CFG034) }

func (r *cfg034) ID() string { return "CFG034" }

// guidanceRe matches Guidance/Handlebars-style role delimiters
// ({{#system~}} … {{/assistant~}}). These mark prompt roles and have no
// legitimate use in plain project documentation.
var guidanceRe = regexp.MustCompile(`\{\{[#/](?:system|user|assistant)~?\}\}`)

// Check flags Guidance role-delimiter syntax in CLAUDE.md. Matches inside fenced
// code blocks are skipped, since a project may legitimately document the Guidance
// library in code examples.
func (r *cfg034) Check(t *Target) []finding.Finding {
	if t == nil || t.InstructionContent == "" {
		return nil
	}
	var findings []finding.Finding
	inFence := false
	for i, line := range strings.Split(t.InstructionContent, "\n") {
		if isFenceDelimiter(line) {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		loc := guidanceRe.FindStringIndex(line)
		if loc == nil {
			continue
		}
		lineNo := i + 1
		findings = append(findings, finding.Finding{
			RuleID:   "CFG034",
			Severity: finding.Warn,
			File:     t.InstructionFile,
			Line:     lineNo,
			Col:      loc[0] + 1,
			Message: t.instructionName() + " line " + strconv.Itoa(lineNo) + " contains Guidance/template role-delimiter syntax (\"" + line[loc[0]:loc[1]] +
				"\") — role markers have no legitimate use in project documentation and suggest an attempt to inject role-delimited content. Remove it",
		})
	}
	return findings
}
