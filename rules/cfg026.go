package rules

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg026 struct{}

var CFG026 = &cfg026{}

func init() { All = append(All, CFG026) }

func (r *cfg026) ID() string { return "CFG026" }

// bypassPattern is one prompt-injection phrase class scanned in CLAUDE.md.
type bypassPattern struct {
	num      int
	re       *regexp.Regexp
	sev      finding.Severity
	label    string
	skipCode bool // pattern 4 only: ignore matches inside fenced / inline code
}

var bypassPatterns = []bypassPattern{
	{1, regexp.MustCompile(`(?i)(ignore|disregard|skip|forget|neglect|overlook|omit|bypass|pay no attention to|do not follow|do not obey)\s*(prior|previous|preceding|above|foregoing|earlier|initial)?\s*(content|text|instructions?|directives?|commands?|context|conversation|inputs?|data|messages?|communication|responses?|requests?)`),
		finding.Error, "instruction override", false},
	{2, regexp.MustCompile(`(?i)(you\s+are\s+now|act\s+as|pretend\s+(you\s+are|to\s+be)|your\s+(new\s+)?(name|identity|persona)\s+is|forget\s+(that\s+)?you\s+are|you\s+have\s+no\s+(restrictions?|limitations?|guidelines?|rules?)|you\s+are\s+(DAN|GPT|an?\s+AI\s+without))`),
		finding.Error, "persona / identity hijacking", false},
	{3, regexp.MustCompile(`(?i)(as\s+(your\s+)?(developer|creator|trainer|Anthropic|operator|administrator|sys(tem)?\s*admin)|this\s+(is|message\s+is)\s+(from\s+)?(Anthropic|your\s+developer)|developer\s+mode\s+(enabled|activated|on)|jailbreak\s+(mode|enabled|activated))`),
		finding.Error, "authority impersonation", false},
	{4, regexp.MustCompile(`(?i)(in\s+a\s+(fictional|hypothetical|alternate|imaginary)\s+(world|scenario|universe|context|story)|for\s+(a\s+)?(story|novel|game|roleplay|simulation|fiction)|hypothetically\s+speaking|in\s+this\s+(roleplay|scenario|simulation),?\s+(you\s+(can|may|should|must|are\s+allowed)))`),
		finding.Warn, "permissive fictional / hypothetical framing", true},
}

// Check scans CLAUDE.md line by line for prompt-injection phrase classes. Patterns
// 1–3 (override, persona hijacking, authority impersonation) are errors and match
// anywhere — an attacker cannot evade them by fencing the text in code. Pattern 4
// (permissive fictional framing) is a warning and is skipped inside code, where
// such phrases are usually legitimate examples.
func (r *cfg026) Check(t *Target) []finding.Finding {
	if t == nil || t.InstructionContent == "" {
		return nil
	}
	var findings []finding.Finding
	inFence := false
	for i, line := range strings.Split(t.InstructionContent, "\n") {
		lineNo := i + 1
		if isFenceDelimiter(line) {
			inFence = !inFence
			continue
		}
		for _, p := range bypassPatterns {
			if p.skipCode && inFence {
				continue
			}
			loc := p.re.FindStringIndex(line)
			if loc == nil {
				continue
			}
			if p.skipCode && inInlineCode(line, loc[0]) {
				continue
			}
			findings = append(findings, finding.Finding{
				RuleID:   "CFG026",
				Severity: p.sev,
				File:     t.InstructionFile,
				Line:     lineNo,
				Col:      loc[0] + 1,
				Message: t.instructionName() + " line " + strconv.Itoa(lineNo) + " contains a prompt-injection phrase (" + p.label + ", pattern " + strconv.Itoa(p.num) +
					") — instruction files are read as trusted system context, so an embedded instruction here can override Claude's behaviour. Remove it",
			})
		}
	}
	return findings
}

func isFenceDelimiter(line string) bool {
	t := strings.TrimSpace(line)
	return strings.HasPrefix(t, "```") || strings.HasPrefix(t, "~~~")
}

// inInlineCode reports whether byte offset idx on line falls inside a backtick
// span (an odd number of backticks precede it).
func inInlineCode(line string, idx int) bool {
	return strings.Count(line[:idx], "`")%2 == 1
}
