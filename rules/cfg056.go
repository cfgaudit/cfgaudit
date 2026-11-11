// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path/filepath"
	"regexp"
	"strings"

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
// scopedTriggerTailRe matches a clause after an always-on trigger that names
// the moment or the task it applies to, so the trigger is not universal after
// all: "Always use when committing changes", "whenever you work with Firebase",
// "BEFORE calling the deploy script", "instead of the built-in tool" (#1658).
// A quantifier is not a scope: "before each task" stays greedy, so "before"
// only narrows with a participle object.
var scopedTriggerTailRe = regexp.MustCompile(`(?i)^\s+(?:when|whenever|while|if|unless|before\s+\w+ing|after\s+\w+ing|instead of|for (?:commits?|code|files?|deployments?|builds?|migrations?|security|tests?))\b`)

// narrowedTriggerTailRe matches a relative clause or a participle after the
// interaction noun, which scopes the trigger to the task it names: "for any
// task touching / needing / requiring ...", "for any request naming `ccmux
// last`" (#1658). It is checked after every pattern, the "always use this" one
// included.
var narrowedTriggerTailRe = regexp.MustCompile(`(?i)^\s+(?:to|that|which|whose|involving|about|against|mentioning|related(?:\s+to)?|or question involving|\w+ing)\b`)

// quantifierTailRe matches a "to" that introduces a universal quantifier
// rather than a task: "Always apply this rule to every request" names the
// requests it applies to, not the work it does, so the trigger stays greedy
// (#1658).
var quantifierTailRe = regexp.MustCompile(`(?i)^\s+to (?:every|any|all|each)\b`)

var greedyTriggerRes = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\buse (?:this|it)\b[^.]{0,40}\bfor (?:everything|anything|all tasks|every task|any task|all requests|every request|any request)\b`),
	regexp.MustCompile(`(?i)\balways (?:use|invoke|run|apply|trigger|call|prefer)\b[^.]{0,70}\b(?:for (?:every|any|all) (?:request|task|message|query)|regardless of (?:the request|the task|what the user asks))\b`),
	regexp.MustCompile(`(?i)\balways (?:use|invoke|run|apply|trigger|call|prefer) (?:this|it)(?: (?:skill|agent|command|tool|rule))?\b`),
	regexp.MustCompile(`(?i)\b(?:for|on|before|after) (?:every|each|any|all) (?:request|task|prompt|message|response|user message|interaction|session|query)s?\b`),
	regexp.MustCompile(`(?i)\bregardless of (?:the (?:task|request)|what the user asks)\b`),
	regexp.MustCompile(`(?i)\bno matter (?:what|the)\b`),
	regexp.MustCompile(`(?i)\bin all (?:cases|situations|contexts|scenarios)\b`),
	regexp.MustCompile(`(?i)\b(?:applies|apply) to (?:all|every|any) (?:requests|tasks|prompts|messages|inputs|interactions)\b`),
	regexp.MustCompile(`(?i)\bhandles? (?:all|every|any) tasks?\b`),
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
	// AGENTS and Copilot instruction documents are always loaded rather
	// than model-selected by their description.
	name := strings.ToLower(filepath.ToSlash(t.InstructionFile))
	if strings.EqualFold(filepath.Base(t.InstructionFile), "AGENTS.md") ||
		strings.HasSuffix(name, "/copilot-instructions.md") {
		return nil
	}
	// A Copilot prompt file runs only when a person invokes it, so nothing
	// selects it by its description (#1467).
	if strings.HasSuffix(name, ".prompt.md") {
		return nil
	}

	// A Cursor .mdc rule is selected by its description only as an "agent
	// requested" rule: alwaysApply false and no globs (#1195). An always-on
	// rule is loaded anyway, and a glob rule by the files it names, so a
	// greedy description adds nothing there.
	mdc := strings.EqualFold(filepath.Ext(t.InstructionFile), ".mdc")
	if mdc && (fm.Bool("alwaysApply") || fm.String("globs") != "" || len(fm.Phrases("globs")) > 0) {
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
				// A relative clause, a participle or a conditional after the
				// match scopes the trigger to the task it names, whichever
				// pattern matched it.
				rest := tf.text[strings.Index(strings.ToLower(tf.text), strings.ToLower(loc))+len(loc):]
				isAlways := strings.HasPrefix(strings.ToLower(loc), "always ")
				narrowed := (narrowedTriggerTailRe.MatchString(rest) && !quantifierTailRe.MatchString(rest)) ||
					(isAlways && scopedTriggerTailRe.MatchString(rest))
				if narrowed {
					continue
				}
				msg := t.instructionName() + " frontmatter " + tf.field + " is a broad/always-on invocation trigger (\"" + loc +
					"\") — Claude auto-selects skills/commands by their description and triggers, so a universal trigger lets this run far beyond its stated purpose; scope it to the specific task it handles"
				if mdc {
					msg = t.instructionName() + " frontmatter " + tf.field + " is a broad/always-on trigger (\"" + loc +
						"\") on an \"agent requested\" Cursor rule (alwaysApply: false, no globs) — Cursor's agent pulls such a rule in by its description, so a universal description makes it apply far beyond its stated purpose; scope the description, or use globs or alwaysApply on purpose"
				}
				return []finding.Finding{{
					RuleID:   "CFG056",
					Severity: finding.Warn,
					File:     t.InstructionFile,
					Message:  msg + userScopeNote(t),
				}}
			}
		}
	}
	return nil
}
