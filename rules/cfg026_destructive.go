// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// Pattern 7 combines three signals in one paragraph: an action addressed to the
// agent, a destructive verb, and a broad target. Keeping them separate avoids
// treating ordinary cleanup instructions or prose that merely describes a
// destructive command as a goal (#1415).
var destructiveActionRe = mustFiltered(`(?i)\b(?:clean|delete|destroy|drop|erase|purge|remove|terminate|wipe)\b`)

var destructiveGoalPrefixRe = regexp.MustCompile(`(?i)(?:\b(?:your|the|primary|main|ultimate)\s+goal\s+(?:is|:)\s+(?:to\s+)?|\b(?:you|the\s+agent|the\s+assistant)\s+(?:must|shall|need(?:s)?\s+to|are\s+to)\s+|\b(?:instruct|tell)\s+(?:the\s+)?(?:agent|assistant)\s+to\s+)[^.!?;]{0,120}$`)

var destructiveCleanTargetRe = regexp.MustCompile(`(?i)factory\s+state|\b(?:entire|whole)\b|home\s+directory|file[- ]?system`)

var destructiveBroadTargetRe = regexp.MustCompile(`(?i)^(?:[^.!?;]{0,160}?\b(` +
	`(?:near[- ]?)?factory\s+state|` +
	`(?:the\s+)?(?:entire|whole)\s+(?:file[- ]?system|system|machine|home\s+directory|user\s+profile)|` +
	`(?:the\s+)?(?:user(?:'s)?\s+)?home\s+directory|` +
	`(?:all|every)\s+(?:of\s+)?(?:the\s+)?(?:user(?:'s)?\s+)?(?:files|data|repositories|branches)\b|` +
	`(?:all|every)\s+(?:of\s+)?(?:the\s+)?(?:(?:cloud|aws|azure|gcp)\s+resources?|(?:(?:aws|ec2|azure|gcp)\s+)?instances?|(?:s3\s+)?buckets?|databases?)\b|` +
	`all\s+(?:of\s+)?(?:the\s+)?(?:users|accounts)|` +
	`file[- ]?system\s+and\s+cloud\s+resources|` +
	`(?:rm\s+-[a-z]*r[a-z]*f|rm\s+-[a-z]*f[a-z]*r)\s+(?:/(?:\s|\z)|~/?(?:\s|\z)|\$HOME/?(?:\s|\z))|` +
	`(?:terminate-instances|delete-user|delete-bucket)\b` +
	`))`)

var destructiveProhibitionRe = regexp.MustCompile(`(?i)\b(?:never|do\s+not|don'?t|must\s+not|mustn'?t|may\s+not|cannot|can'?t|avoid|refuse\s+to|forbidden\s+to|prohibited\s+from|not\s+allowed\s+to)[\s,]+(?:[\w,]+\s+){0,6}$`)

// A condition or a request for consent before the verb: "ask before you delete
// all files" keeps a person in the loop.
var destructiveConditionRe = regexp.MustCompile(`(?i)\b(?:ask|confirm|before|if|unless|when|until)\b[^.!?;]*$`)

// Text between the verb and the target that makes the target something else
// than the verb's object: "remove the header from all files", "clean the cache
// and rebuild all repositories".
var destructiveDetachedTargetRe = regexp.MustCompile(`(?i)\b(?:from|and|then)\b|,`)

var destructiveExamplePrefixRe = regexp.MustCompile(`(?i)\b(?:example|sample|documentation|documented\s+command|anti-?pattern|warning|danger|risk)\s*:?\s*$`)

var destructiveProtectedTargetRe = regexp.MustCompile(`(?i)\b(?:refus\w*|reject\w*|block\w*|prevent\w*|guard\w*|protect\w*|avoid\w*)\b`)

// A quantifier does not make a target broad when the rest of the phrase
// narrows it to a named subset or a repository-local cleanup directory.
var destructiveScopedTargetRe = regexp.MustCompile(`(?i)^\s*(?:` +
	`(?:marked|matching|listed|selected|specified|stale|unused|expired|test)\b|` +
	`(?:except|excluding|but|that|which|you|after|of|for|from)\b|` +
	`(?:in|under|within|from)\s+(?:\.{0,2}/|this\s+directory\b|the\s+(?:build|dist|output|temporary|temp|cache|current|selected|specified|target)\b)|` +
	`(?:in|under|within|from)\s+` + "`?" + `\.[\w-]+` + "`?" + `\s+director(?:y|ies)\b|` +
	`of\s+(?:the\s+)?(?:keys?|entries|items?|records?|matches|occurrences)\b|` +
	`created\s+(?:by|for)\s+(?:this|the)\s+(?:test|project|run)\b|` +
	`:\s*` + "`?" + `(?:GET|POST|PUT|PATCH|DELETE)\b` +
	`)`)

// A location narrows the target unless it is itself as broad as the target.
var destructiveLocationRe = regexp.MustCompile(`(?i)^\s*(?:in|on|under|within)\b`)

var destructiveBroadLocationRe = regexp.MustCompile(`(?i)^\s*(?:in|on|under|within)\s+(?:(?:the|this|your|my|our)\s+)?(?:(?:entire|whole|user(?:'s)?|cloud|aws|azure|gcp)\s+)?(?:account|organi[sz]ation|subscription|tenant|machine|system|file[- ]?system|disk|drive|home\b|~|/(?:\s|$))`)

var destructiveAPIHeadingRe = regexp.MustCompile(`(?i)^#{2,6}\s+[^\n]*(?:\([^\n)]*\)|\bAPI\b)\s*$`)

type instructionParagraph struct {
	text      string
	startLine int
	lead      string
}

func instructionParagraphs(content string) []instructionParagraph {
	lines := strings.Split(content, "\n")
	var out []instructionParagraph
	var paragraph []string
	start := 1
	inFence := false
	previousNonBlank := ""
	lead := ""
	flush := func() {
		if len(paragraph) == 0 {
			return
		}
		out = append(out, instructionParagraph{text: strings.Join(paragraph, "\n"), startLine: start, lead: lead})
		previousNonBlank = paragraph[len(paragraph)-1]
		paragraph = nil
	}
	for i, line := range lines {
		if isFenceDelimiter(line) {
			flush()
			inFence = !inFence
			continue
		}
		if inFence || strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if len(paragraph) > 0 && listItemRe.MatchString(line) {
			flush()
		}
		if len(paragraph) == 0 {
			start = i + 1
			lead = previousNonBlank
		}
		paragraph = append(paragraph, line)
	}
	flush()
	return out
}

func destructiveGoalFinding(src instructionSource) []finding.Finding {
	var findings []finding.Finding
	for _, paragraph := range instructionParagraphs(src.Content) {
		if destructiveAPIHeadingRe.MatchString(paragraph.lead) {
			continue
		}
		for _, action := range destructiveActionRe.FindAllStringIndex(paragraph.text, -1) {
			before := paragraph.text[:action[0]]
			lineStart := strings.LastIndex(before, "\n") + 1
			lead := before[lineStart:]
			isLineStart := strings.TrimSpace(strings.TrimLeft(lead, "-*+0123456789.) \t")) == ""
			isImperative := isLineStart && (lineStart == 0 || paragraph.text[action[0]] >= 'A' && paragraph.text[action[0]] <= 'Z')
			if !isImperative && !destructiveGoalPrefixRe.MatchString(before) {
				continue
			}
			if destructiveProhibitionRe.MatchString(before) || destructiveExamplePrefixRe.MatchString(before) || destructiveConditionRe.MatchString(before) {
				continue
			}
			target := destructiveBroadTargetRe.FindStringSubmatchIndex(paragraph.text[action[1]:])
			if target == nil {
				continue
			}
			targetEnd := action[1] + target[1]
			between := paragraph.text[action[1]:targetEnd]
			if destructiveProtectedTargetRe.MatchString(between) || strings.Contains(between, ":") {
				continue
			}
			if destructiveDetachedTargetRe.MatchString(paragraph.text[action[1] : action[1]+target[2]]) {
				continue
			}
			// "Clean" is everyday wording: only a whole-machine target makes it
			// destructive, as in the published "clean a system to a near-factory
			// state".
			if strings.EqualFold(paragraph.text[action[0]:action[1]], "clean") && !destructiveCleanTargetRe.MatchString(between) {
				continue
			}
			afterTarget := paragraph.text[targetEnd:]
			if destructiveScopedTargetRe.MatchString(afterTarget) ||
				(destructiveLocationRe.MatchString(afterTarget) && !destructiveBroadLocationRe.MatchString(afterTarget)) {
				continue
			}
			line := paragraph.startLine + strings.Count(paragraph.text[:action[0]], "\n")
			col := action[0] - strings.LastIndex(paragraph.text[:action[0]], "\n")
			findings = append(findings, finding.Finding{
				RuleID:   "CFG026",
				Severity: finding.Error,
				File:     src.File,
				Line:     line,
				Col:      col,
				Message:  src.Name + " line " + strconv.Itoa(line) + " gives the agent a destructive goal against a broad target (pattern 7) — instruction files are read as trusted system context, so this can make the agent wipe user data or cloud infrastructure. Remove the instruction",
			})
			break
		}
	}
	return findings
}
