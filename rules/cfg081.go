// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg081 struct{}

var CFG081 = &cfg081{}

func init() { All = append(All, CFG081) }

func (r *cfg081) ID() string { return "CFG081" }

// compactionSurvivalRe matches an instruction telling the agent to make its own
// directives outlive a context-window compaction / summarization / session
// boundary — a persistence primitive that turns a one-shot injected instruction
// into a durable one. The discriminator that keeps this distinct from ordinary
// "follow these rules" guidance is the trailing boundary clause: a persistence
// verb applied to an instruction noun *across a compaction/summarization/session
// boundary*. Ordinary emphasis ("always follow these rules") lacks that clause
// and does not match.
var compactionSurvivalRe = mustFiltered(`(?i)\b` +
	// persistence verb
	`(?:never\s+forget|do\s+not\s+(?:remove|drop|discard|forget|delete)|don'?t\s+(?:remove|drop|discard|forget|delete)|preserve|retain|keep|maintain|persist|remember|carry\s+(?:over|forward)|re-?inject|re-?add)\s+` +
	// optional determiner
	`(?:this|these|those|the\s+following|the\s+above|all\s+(?:of\s+)?(?:the\s+)?|your\s+)?\s*` +
	// instruction noun
	`((?:instruction|directive|rule|requirement|command|setting|behaviou?r|prompt|guideline|note|memory)s?|memories)` +
	// small adverbial gap (e.g. "verbatim", "at all times")
	`\s+((?:\w+\s+){0,3}?)` +
	// boundary clause — the discriminator
	`(?:` +
	`(?:across|through|throughout|during|after|beyond|past|surviving|to\s+survive)\s+(?:the\s+|a\s+|any\s+|each\s+|every\s+)?(?:context(?:\s+window)?|compaction|compression|summari[sz]ation|summari[sz]ing|truncation)` +
	`|(?:across|between|into|beyond|for|in)\s+(?:future\s+|later\s+|new\s+|subsequent\s+|all\s+|other\s+)?sessions?` +
	`|(?:new|future|later|subsequent)\s+sessions?` +
	`)`)

// storedDataGapRe matches a data noun right after the instruction noun, which
// then qualifies it: "persist requirements context across sessions" keeps
// context, not a requirement (#958).
var storedDataGapRe = regexp.MustCompile(`(?i)^(?:context|state|data|history|notes?|progress|preferences)\b`)

// storesData reports a match whose object is stored data rather than an
// instruction: "Persist memory across sessions" documents a memory feature,
// and "persist requirements context across sessions" saves context to a
// memory server (#958). Such a line is reported as a warning.
func storesData(line string, sm []int) bool {
	noun := strings.ToLower(line[sm[2]:sm[3]])
	return noun == "memory" || noun == "memories" || storedDataGapRe.MatchString(line[sm[4]:sm[5]])
}

// Check scans each instruction source for a compaction-survival persistence
// directive. Claude Code compresses (compacts / summarizes) its context as a
// conversation grows; an instruction file that tells the agent to keep a
// directive *across* that boundary is trying to make an injected instruction
// durable so it re-asserts in later turns and sessions. Reports the line and the
// matched phrase.
func (r *cfg081) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	for _, src := range t.instructionSources() {
		inFence := false
		for i, line := range strings.Split(src.Content, "\n") {
			if isFenceDelimiter(line) {
				inFence = !inFence
				continue
			}
			if inFence {
				continue // a doc demonstrating the pattern, not using it
			}
			sm := compactionSurvivalRe.FindStringSubmatchIndex(line)
			if sm == nil {
				continue
			}
			loc := sm[:2]
			sev := finding.Error
			if storesData(line, sm) {
				sev = finding.Warn
			}
			lineNo := i + 1
			msg := src.Name + " line " + strconv.Itoa(lineNo) + ` tells the agent to keep an instruction across context compaction / summarization / sessions ("` + collapseWS(line[loc[0]:loc[1]]) +
				`") — a persistence directive that makes an injected instruction durable so it re-asserts after the context is compressed; trusted guidance has no reason to fight context compaction. Remove it`
			if sev == finding.Warn {
				msg = src.Name + " line " + strconv.Itoa(lineNo) + ` keeps memory or context across sessions ("` + collapseWS(line[loc[0]:loc[1]]) +
					`") — usually a memory feature; confirm that no instruction is meant to survive context compaction with it`
			}
			findings = append(findings, finding.Finding{
				RuleID:   "CFG081",
				Severity: sev,
				File:     src.File,
				Line:     lineNo,
				Col:      loc[0] + 1,
				Message:  msg,
			})
		}
	}
	return findings
}
