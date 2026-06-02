package rules

import (
	"regexp"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

type cfg056 struct{}

var CFG056 = &cfg056{}

func init() { All = append(All, CFG056) }

func (r *cfg056) ID() string { return "CFG056" }

// greedyTriggerRes match a frontmatter description that tells Claude to invoke a
// skill/command/subagent universally — for every request rather than a specific
// task. A greedy trigger lets a committed skill hijack model behaviour well
// beyond its stated purpose. Patterns are anchored on an explicit universal
// quantifier + an interaction noun so scoped descriptions ("deploy the app",
// "review code for security issues") don't match.
var greedyTriggerRes = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\buse (?:this|it)\b[^.]{0,40}\bfor (?:everything|anything|all tasks|every task|any task|all requests|every request|any request)\b`),
	regexp.MustCompile(`(?i)\balways (?:use|invoke|run|apply|trigger|call|prefer)\b`),
	regexp.MustCompile(`(?i)\b(?:for|on|before|after) (?:every|each|any|all) (?:request|task|prompt|message|response|user message|interaction|session|query)s?\b`),
	regexp.MustCompile(`(?i)\bregardless of\b`),
	regexp.MustCompile(`(?i)\bno matter (?:what|the)\b`),
	regexp.MustCompile(`(?i)\bin all (?:cases|situations|contexts|scenarios)\b`),
	regexp.MustCompile(`(?i)\b(?:applies|apply) to (?:all|every|any) (?:requests|tasks|prompts|messages|inputs|interactions)\b`),
}

// Check flags a model-invocable instruction file whose frontmatter description is
// a greedy/always-on invocation trigger. Claude selects skills and slash commands
// by their description, so a universal trigger in a committed file is a
// behaviour-hijack vector. Files that opt out of model invocation
// (disable-model-invocation: true) cannot be auto-triggered and are not flagged.
func (r *cfg056) Check(t *Target) []finding.Finding {
	if t == nil || t.InstructionContent == "" {
		return nil
	}
	fm, ok := parser.InstructionFrontmatter(t.InstructionContent)
	if !ok {
		return nil
	}
	if fm.Bool("disable-model-invocation") {
		return nil
	}
	desc := fm.String("description")
	if desc == "" {
		return nil
	}
	for _, re := range greedyTriggerRes {
		if loc := re.FindString(desc); loc != "" {
			return []finding.Finding{{
				RuleID:   "CFG056",
				Severity: finding.Warn,
				File:     t.InstructionFile,
				Message: t.instructionName() + " frontmatter description is a broad/always-on invocation trigger (\"" + loc +
					"\") — Claude auto-selects skills/commands by their description, so a universal trigger lets this run far beyond its stated purpose; scope the description to the specific task it handles" + userScopeNote(t),
			}}
		}
	}
	return nil
}
