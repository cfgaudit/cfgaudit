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

// Check flags a model-invocable instruction file whose frontmatter declares a
// greedy/always-on invocation trigger — in the `description` Claude selects on,
// or in an explicit `triggers` field. A universal trigger in a committed file is
// a behaviour-hijack vector. Files that opt out of model invocation
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

	// Each greedy-trigger surface, in report order: the description first, then
	// every entry of the explicit triggers field.
	type triggerField struct{ field, text string }
	var fields []triggerField
	if desc := fm.String("description"); desc != "" {
		fields = append(fields, triggerField{"description", desc})
	}
	for _, tr := range fm.Phrases("triggers") {
		fields = append(fields, triggerField{"triggers", tr})
	}

	for _, tf := range fields {
		for _, re := range greedyTriggerRes {
			if loc := re.FindString(tf.text); loc != "" {
				return []finding.Finding{{
					RuleID:   "CFG056",
					Severity: finding.Warn,
					File:     t.InstructionFile,
					Message: t.instructionName() + " frontmatter " + tf.field + " is a broad/always-on invocation trigger (\"" + loc +
						"\") — Claude auto-selects skills/commands by their description and triggers, so a universal trigger lets this run far beyond its stated purpose; scope it to the specific task it handles" + userScopeNote(t),
				}}
			}
		}
	}
	return nil
}
