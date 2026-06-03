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
var permissionBypassRe = regexp.MustCompile(`(?i)(` +
	`always\s+approve` +
	`|auto-?approve` +
	`|bypass\s+(?:permission|confirmation|approval)` +
	`|skip\s+(?:confirm(?:ation)?|approval|the\s+prompt)` +
	`|without\s+(?:confirm(?:ation)?|approval|prompt(?:ing)?)` +
	`|never\s+(?:prompt|confirm|require\s+approval)` +
	`|(?:without\s+asking|never\s+ask(?:ing)?|do\s+not\s+ask|don'?t\s+ask|do\s+not\s+prompt)\s+(?:the\s+user\s+)?(?:for\s+)?(?:permission|approval|confirmation|before\s+(?:running|executing|proceeding|making|applying|doing))` +
	`)`)

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
