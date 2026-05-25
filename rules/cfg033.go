package rules

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg033 struct{}

var CFG033 = &cfg033{}

func init() { All = append(All, CFG033) }

func (r *cfg033) ID() string { return "CFG033" }

var (
	// mdImageRe captures the URL of an inline markdown image: ![alt](http(s)://…).
	mdImageRe = regexp.MustCompile(`!\[[^\]]*\]\(\s*(https?://[^)\s]+)\s*\)`)
	// emptyQueryParamRe matches a query parameter with an empty value (name= then
	// & or end) — the LLM is expected to fill it with conversation data.
	emptyQueryParamRe = regexp.MustCompile(`[?&][A-Za-z_][\w.\-]*=(?:&|$)`)
	// urlPlaceholderRe matches a placeholder the LLM might fill: {{…}}, <…>, __…__.
	urlPlaceholderRe = regexp.MustCompile(`\{\{[^}]*\}\}|<[A-Za-z_][^>]*>|__[A-Za-z]\w*__`)
)

// Check flags markdown image references whose URL has an empty or placeholder
// query parameter. Claude is then instructed to fill it with conversation data,
// and rendering/following the image URL exfiltrates that data to the attacker's
// server (the classic markdown-image exfiltration technique).
func (r *cfg033) Check(t *Target) []finding.Finding {
	if t == nil || t.InstructionContent == "" {
		return nil
	}
	var findings []finding.Finding
	for i, line := range strings.Split(t.InstructionContent, "\n") {
		for _, m := range mdImageRe.FindAllStringSubmatchIndex(line, -1) {
			url := line[m[2]:m[3]]
			if !emptyQueryParamRe.MatchString(url) && !urlPlaceholderRe.MatchString(url) {
				continue
			}
			lineNo := i + 1
			findings = append(findings, finding.Finding{
				RuleID:   "CFG033",
				Severity: finding.Error,
				File:     t.InstructionFile,
				Line:     lineNo,
				Col:      m[0] + 1,
				Message: t.instructionName() + " line " + strconv.Itoa(lineNo) + " contains a markdown image with an empty/placeholder query parameter (\"" + url +
					"\") — a data-exfiltration sink: Claude is led to fill the parameter with conversation data, which leaks when the image URL is rendered or fetched. Remove it",
			})
		}
	}
	return findings
}
