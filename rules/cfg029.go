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

// permissionBypassRe matches CLAUDE.md text that instructs Claude to auto-approve
// or skip confirmation — disabling the permission system via system context, the
// natural-language equivalent of defaultMode: bypassPermissions (CFG004).
var permissionBypassRe = regexp.MustCompile(`(?i)(always\s+approve|auto-?approve|without\s+(?:asking|confirm(?:ation)?|prompt(?:ing)?|approval)|never\s+(?:ask|prompt|confirm|require\s+approval)|skip\s+confirm(?:ation)?|do\s+not\s+(?:ask|prompt|confirm)|bypass\s+(?:permission|confirmation|approval))`)

func (r *cfg029) Check(t *Target) []finding.Finding {
	if t == nil || t.InstructionContent == "" {
		return nil
	}
	var findings []finding.Finding
	for i, line := range strings.Split(t.InstructionContent, "\n") {
		loc := permissionBypassRe.FindStringIndex(line)
		if loc == nil {
			continue
		}
		lineNo := i + 1
		findings = append(findings, finding.Finding{
			RuleID:   "CFG029",
			Severity: finding.Error,
			File:     t.InstructionFile,
			Line:     lineNo,
			Col:      loc[0] + 1,
			Message: t.instructionName() + " line " + strconv.Itoa(lineNo) + " instructs Claude to bypass permission prompts (\"" + line[loc[0]:loc[1]] +
				"\") — this disables the permission system via system-context text, equivalent to defaultMode: bypassPermissions (CFG004). Remove it",
		})
	}
	return findings
}
