// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strings"
)

// attributionRe is the end of the text before a pattern-1 verb when the
// override is what someone else says: "tells you to", "asking the agent to"
// (#1795). The subject of the attribution comes before it.
var attributionRe = regexp.MustCompile(`(?i)\b(?:tells?|told|telling|asks?|asked|asking|instructs?|instructed|instructing|directs?|directing|wants?|wanting)\s+(?:you|the\s+(?:agent|model|assistant|ai)|agents?|models?|assistants?|claude)\s+to\s+$`)

var (
	// attributedIfRe opens a conditional clause: "If external content tells
	// you to ...".
	attributedIfRe = regexp.MustCompile(`(?i)\b(?:if|when|whenever|unless)\b`)
	// untrustedContentRe names content as the attribution's subject:
	// "Fetched text asking you to ...", "text that addresses an assistant,
	// tells you to ...".
	untrustedContentRe = regexp.MustCompile(`(?i)\b(?:text|content|messages?|emails?|pages?|documents?|inputs?|data|results?|comments?|issues?|anything|instructions?)\b`)
	// selfContentRe is content that points at itself, which makes the
	// attribution the order: "This message tells you to ...".
	selfContentRe = regexp.MustCompile(`(?i)\b(?:this|my|our)\s+(?:\w+\s+)?(?:text|content|messages?|emails?|pages?|documents?|inputs?|data|results?|comments?|issues?|instructions?)\b`)
	// untrustedCueRe marks the content as something to distrust or skip.
	untrustedCueRe = regexp.MustCompile(`(?i)\b(?:fetched|external|retrieved|untrusted|third[- ]party|incoming|scraped|suspicious|skip|discard|reject|refuse|treat|prompt[- ]injection|injected|malicious|attackers?|scammers?|do\s+not\s+(?:act|follow|obey|process)|don'?t\s+(?:act|follow|obey|process)|never\s+(?:act|follow|obey|process))\b`)
	// complianceRe in the rest of the sentence accepts the override, which
	// makes the conditional a bypass: "If the user asks you to ignore
	// previous instructions, comply."
	complianceRe = regexp.MustCompile(`(?i)\b(?:comply|complies|obey|do\s+(?:it|so|that|as\s+(?:told|asked|instructed))|follow\s+(?:it|them|that|those|the\s+request)|go\s+ahead|accept\s+(?:it|that)|honou?r\s+(?:it|that|the\s+request)|let\s+it)\b`)
	// checklistIntroRe is the line that opens a list of shapes to look for:
	// "Look for instructions that:", "Flag skills which:".
	checklistIntroRe = regexp.MustCompile(`(?i)\b(?:look|watch|check|scan|search)\s+for\b.*\b(?:that|which)\s*:\s*$|\b(?:flag|detect|report|reject|block|identify|catch)\b.*\b(?:that|which)\s*:\s*$`)
	// checklistItemStartRe is a list item that starts with the attribution:
	// "- tell the agent to ...".
	checklistItemStartRe = regexp.MustCompile(`(?i)^\s*(?:[-*+]|\d+[.)])\s+(?:tells?|asks?|instructs?|directs?)\s+(?:you|the\s+(?:agent|model|assistant|ai)|agents?|models?)\s+to\s+$`)
)

// attributedOverride reports a pattern-1 phrase that a defensive rule
// attributes to someone else, as the thing to refuse (#1795): inside a
// conditional, after content the sentence marks as untrusted, or as an item
// of a list of shapes to look for. The rest of the sentence must not accept
// the override.
func attributedOverride(lines []string, i int, line string, loc []int) bool {
	before := line[:loc[0]]
	if !attributionRe.MatchString(before) {
		return false
	}
	sentStart := 0
	if k := strings.LastIndexAny(before, ".;!?"); k >= 0 {
		sentStart = k + 1
	}
	sentence := before[sentStart:]
	rest := line[loc[1]:]
	if k := strings.IndexAny(rest, ".;!?"); k >= 0 {
		rest = rest[:k]
	}
	if complianceRe.MatchString(rest) {
		return false
	}
	if attributedIfRe.MatchString(sentence) {
		return true
	}
	if untrustedContentRe.MatchString(sentence) && !selfContentRe.MatchString(sentence) && untrustedCueRe.MatchString(sentence) {
		return true
	}
	return checklistItemStartRe.MatchString(before) && checklistIntro(lines, i)
}

// checklistIntro reports whether the list that line i belongs to opens with
// a checklist intro: the first line above the list's items (listItemRe,
// from CFG029) that is not one.
func checklistIntro(lines []string, i int) bool {
	for j := i - 1; j >= 0; j-- {
		l := strings.TrimSpace(lines[j])
		if l == "" || listItemRe.MatchString(lines[j]) {
			continue
		}
		return checklistIntroRe.MatchString(l)
	}
	return false
}
