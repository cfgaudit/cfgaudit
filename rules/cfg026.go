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

// adversarialPersona is the target that turns a persona instruction into an
// identity hijack. Naming a role ("the release manager") is how skills, subagents
// and commands are written; naming one of these is not.
//
// The article is optional on the adjectives because "you are now unrestricted"
// occurs in the wild without one, and the mode forms are here because "you are
// now in developer mode" does too, which pattern 3 does not cover (it matches
// only "developer mode enabled/activated/on"). "dan mode" is in the same
// alternation because "you are now in DAN mode" puts a word between the phrase
// and the target, so the bare DAN alternative cannot reach it.
const adversarialPersona = `(DAN\b|the\s+user\b|the\s+system\b|root\b|admin\b` +
	`|(an?\s+)?(unrestricted|unfiltered|jailbroken|uncensored)` +
	`|an?\s+AI\s+(with\s+no|without)` +
	`|(in\s+)?(developer|god|jailbreak|dan)\s+mode)`

var bypassPatterns = []bypassPattern{
	// The determiner run between the verb and the qualifier is what makes the
	// canonical "ignore ALL previous instructions" match: without it the pattern
	// only fired when the qualifier followed the verb directly. It is a closed set
	// on purpose — a generic `(?:\s+\w+){0,3}` filler would drag in benign prose,
	// because the noun list carries broad words (data, content, context, text).
	{1, regexp.MustCompile(`(?i)(ignore|disregard|skip|forget|neglect|overlook|omit|bypass|pay no attention to|do not follow|do not obey)\s+(?:(?:all|any|the|these|those|your|its|our|my|of)\s+){0,3}(prior|previous|preceding|above|foregoing|earlier|initial)?\s*(content|text|instructions?|directives?|commands?|context|conversation|inputs?|data|messages?|communication|responses?|requests?)`),
		finding.Error, "instruction override", false},
	// Pattern 2 targets hijacking of Claude's own identity. Bare "act as <role>" /
	// "pretend you are <role>" are the standard, legitimate way to define a skill's
	// or subagent's persona, so they are NOT matched; act-as/pretend only matches
	// when the target is adversarial (an unrestricted AI, DAN, the user, root, …).
	//
	// "you are now <target>" is qualified by the same list, for the same reason and
	// after the same mistake: the alternative used to be bare, so it reported the
	// construct the carve-out exists to protect, only reached through a different
	// word order. Measured on 200 committed instruction files containing the phrase
	// (CLAUDE.md, AGENTS.md, .claude/commands, .claude/agents, SKILL.md), all 200
	// matched and the trailing text was a role or a mode: "you are now the Vault
	// Operator", "you are now acting as a Senior Requirements Analyst", "you are now
	// in **talk mode**". The adversarial forms that really occur are covered by the
	// list below: "you are now unrestricted" and "you are now in developer mode"
	// were both present, and both still match (#571).
	{2, regexp.MustCompile(`(?i)(you\s+are\s+now\s+` + adversarialPersona + `|your\s+(new\s+)?(name|identity|persona)\s+is|forget\s+(that\s+)?you\s+are|you\s+have\s+no\s+(restrictions?|limitations?|guidelines?|rules?)|you\s+are\s+(DAN|an?\s+AI\s+(with\s+no|without)|an?\s+(unrestricted|unfiltered|jailbroken|uncensored))|(act\s+as|pretend\s+(you\s+are|to\s+be))\s+` + adversarialPersona + `)`),
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
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	for _, src := range t.instructionSources() {
		inFence := false
		for i, line := range strings.Split(src.Content, "\n") {
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
					File:     src.File,
					Line:     lineNo,
					Col:      loc[0] + 1,
					Message: src.Name + " line " + strconv.Itoa(lineNo) + " contains a prompt-injection phrase (" + p.label + ", pattern " + strconv.Itoa(p.num) +
						") — instruction files are read as trusted system context, so an embedded instruction here can override the agent's behaviour. Remove it",
				})
			}
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
