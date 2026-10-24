// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg113 struct{}

// CFG113 reports an instruction to fetch remote text and follow it.
var CFG113 = &cfg113{}

func init() { All = append(All, CFG113) }

func (r *cfg113) ID() string { return "CFG113" }

var (
	fetchURLRe = regexp.MustCompile(`https?://\S+`)

	// fetchFollowRe is a load verb, then within the same sentence an obey verb
	// whose object is instructions ("fetch the instructions at X and follow
	// them", "read X and follow the runbook").
	fetchFollowRe = regexp.MustCompile(`(?i)\b(?:fetch|download|retrieve|read|load|open|curl|wget|pull)\b.{0,160}?` +
		`\b(follow|execute|run|apply|obey|carry\s+out|adopt|do\s+what)\b` +
		`(?:\s+(?:all\s+|every\s+|each\s+)?(?:of\s+)?(?:the|its|these|those|their|that|this)?\s*(?:[\w-]+\s+){0,2}?(?:instructions?|steps?|commands?|directions?|runbook|rules?|guidance|directives?|prompts?)\b|\s+(?:them|it)\b)`)

	// fetchFollowLinkRe is the form whose object is the link itself:
	// "fetch and follow the [Style Guide](https://...)", "fetch and follow
	// `https://.../llms.txt`".
	fetchFollowLinkRe = regexp.MustCompile("(?i)\\b(?:fetch|download|retrieve|read|load)\\s+and\\s+(follow|execute|run|apply|obey)\\s+(?:the\\s+)?(?:\\[[^\\]]*\\]\\(\\s*https?://|`?<?https?://)")

	// sentenceEndRe splits a line into sentences: a terminal mark followed by
	// whitespace. A dot inside a URL or a file name (AGENTS.md) does not end one.
	sentenceEndRe = regexp.MustCompile(`[.!?]\s+`)
)

// relayVerbRe ends the text before a quotation the agent is told to pass on
// to the person: tell the user: "...", Guide: "...", say "...".
var relayVerbRe = regexp.MustCompile(`(?i)\b(?:tell|tells|say|says|show|shows|guide|guides|instruct|instructs|ask|asks|inform|informs|explain|explains|reply|replies|respond|responds|message|print|output|display|suggest|suggests|recommend|recommends|prompt|prompts)\b[^"“”]{0,40}$`)

// relayedToUser reports whether pos in line lies inside a quotation that the
// agent is told to relay to the person ("tell the user: \"Open https://... in
// your browser and copy/run the installation command\""), so the load and obey
// verbs are the person's, not the agent's (#824).
func relayedToUser(line string, pos int) bool {
	open := -1
	for i, r := range line {
		if i > pos {
			break
		}
		switch r {
		case '"':
			if open >= 0 {
				open = -1
			} else {
				open = i
			}
		case '“':
			open = i
		case '”':
			open = -1
		}
	}
	return open >= 0 && relayVerbRe.MatchString(line[:open])
}

// Check reports a sentence in an instruction file that tells the agent to load
// text from a URL and follow it (#621).
//
// The instruction file is reviewed; the text at the URL is not, and it can
// change after review. A committed line that hands the agent's behaviour to a
// remote file moves the real payload out of the repository, which is the class
// AVE-2026-00001 describes as a metamorphic payload via external config fetch.
// It is indirect prompt injection by design rather than by accident.
//
// Two shapes are matched within one sentence that holds a URL: a load verb
// followed by an obey verb whose object is instructions, steps, rules or "it" /
// "them" ("Fetch and follow the instructions at: https://..."), and "fetch and
// follow" whose object is the link itself ("fetch and follow the [Style
// Guide](https://...)"). A documentation link without a load verb ("Follow
// Semantic Versioning (https://...)", "Run PageSpeed Insights at https://...")
// is not matched. Fenced code is skipped.
//
// warn by default: real files use it for shared team guidelines and for
// vendor-published agent instructions (llms.txt). error when the verb is
// execute, run or obey, which asks the agent to act on the fetched content
// rather than read it.
//
// Measured on 1162 instruction files seeded on the phrasings this rule targets:
// 399 sentences hold a URL and an obey verb, 53 match (13 distinct wordings),
// and every distinct wording is a fetch-and-follow instruction.
func (r *cfg113) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	for _, src := range t.instructionSources() {
		fenced := fencedLines(src.Content)
		for i, line := range strings.Split(src.Content, "\n") {
			ln := i + 1
			if fenced[ln] || !fetchURLRe.MatchString(line) {
				continue
			}
			off := 0
			for _, sentence := range sentenceEndRe.Split(line, -1) {
				start := off
				if i := strings.Index(line[off:], sentence); i >= 0 {
					start = off + i
					off = start + len(sentence)
				}
				if !fetchURLRe.MatchString(sentence) {
					continue
				}
				m := fetchFollowRe.FindStringSubmatchIndex(sentence)
				if m == nil {
					m = fetchFollowLinkRe.FindStringSubmatchIndex(sentence)
				}
				if m == nil || relayedToUser(line, start+m[0]) {
					continue
				}
				sev := finding.Warn
				verb := strings.ToLower(strings.Join(strings.Fields(sentence[m[2]:m[3]]), " "))
				if verb == "execute" || verb == "run" || verb == "obey" {
					sev = finding.Error
				}
				url := fetchURLRe.FindString(sentence)
				findings = append(findings, finding.Finding{
					RuleID:   "CFG113",
					Severity: sev,
					File:     src.File,
					Line:     ln,
					Message: src.Name + " line " + strconv.Itoa(ln) + " tells the agent to fetch " + quoteValue(strings.TrimRight(url, ")`>].,;")) + " and " + verb +
						" what it says: the reviewed file hands the agent's behaviour to remote text nobody reviewed, which can change at any time (the external-fetch payload class). Copy the instructions into the repository, or pin them to a reviewed revision",
				})
				break
			}
		}
	}
	return findings
}
