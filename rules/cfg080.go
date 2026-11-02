// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg080 struct{}

var CFG080 = &cfg080{}

func init() { All = append(All, CFG080) }

func (r *cfg080) ID() string { return "CFG080" }

// mdCommentRe captures the title of a Markdown link reference definition whose
// destination is "#" or "<>", the idiom `[//]: # (text)` that Markdown writers
// use as a comment (#621). A link reference definition does not render
// (CommonMark spec, section 4.7), and the title can be in parentheses, double
// or single quotes. Up to three spaces of indent, as the spec allows. One of
// submatches 1-3 is the title.
var mdCommentRe = regexp.MustCompile(`(?m)^ {0,3}\[[^\]\n]*\]:[ \t]*(?:#|<>)[ \t]+(?:\(([^)\n]*)\)|"([^"\n]*)"|'([^'\n]*)')[ \t]*$`)

// commentSpan is a comment found in an instruction file: its body and the byte
// offset where the comment starts.
type commentSpan struct {
	body  string
	start int
	kind  string
}

// htmlCommentSpans returns every HTML comment in content, ending each one the
// way the HTML tokenizer does. A "<!--" that starts a line (up to three spaces
// of indent) opens an HTML block: it ends at "-->" or "--!>", and one that is
// never closed hides everything after the marker (#971), so it runs to the end
// of content. Elsewhere it is inline HTML, which only forms a comment when
// closed with "-->" (plus the abrupt empty forms "<!-->" and "<!--->"); an
// unclosed mid-line "<!--" stays visible text and is not a comment, so the
// directive after it is not concealed (review on #971).
func htmlCommentSpans(content string) []commentSpan {
	var out []commentSpan
	for offset := 0; ; {
		i := strings.Index(content[offset:], "<!--")
		if i < 0 {
			return out
		}
		start := offset + i
		body, next, ok := htmlCommentBody(content, start+len("<!--"), startsLine(content, start))
		if !ok {
			offset = start + len("<!--")
			continue
		}
		out = append(out, commentSpan{body: body, start: start, kind: "an HTML comment (<!-- … -->"})
		if next >= len(content) {
			return out
		}
		offset = next
	}
}

// startsLine reports whether off begins a line after at most three spaces of
// indentation, the CommonMark condition for an HTML block.
func startsLine(content string, off int) bool {
	lineStart := strings.LastIndexByte(content[:off], '\n') + 1
	indent := content[lineStart:off]
	return len(indent) <= 3 && strings.Trim(indent, " ") == ""
}

// htmlCommentBody returns the body of the comment whose text starts at
// bodyStart, the offset just past its closing delimiter, and whether it is a
// comment at all. block selects HTML-block rules: "--!>" also closes, and an
// unclosed comment returns the rest of content with next == len(content).
// Inline (mid-line) comments close only with "-->"; an unclosed one is visible
// text, reported with ok == false.
func htmlCommentBody(content string, bodyStart int, block bool) (string, int, bool) {
	rest := content[bodyStart:]
	// "<!-->" and "<!--->" are complete empty comments, not an opener followed
	// by visible text (HTML tokenizer: abrupt-closing-of-empty-comment).
	if strings.HasPrefix(rest, ">") {
		return "", bodyStart + 1, true
	}
	if strings.HasPrefix(rest, "->") {
		return "", bodyStart + 2, true
	}
	end, term := -1, 0
	if i := strings.Index(rest, "-->"); i >= 0 {
		end, term = i, len("-->")
	}
	if block {
		if i := strings.Index(rest, "--!>"); i >= 0 && (end < 0 || i < end) {
			end, term = i, len("--!>")
		}
		if end < 0 {
			return rest, len(content), true
		}
	} else if end < 0 {
		return "", 0, false
	}
	return rest[:end], bodyStart + end + term, true
}

// commentSpans returns every HTML comment and Markdown link-reference comment
// in content.
func commentSpans(content string) []commentSpan {
	out := htmlCommentSpans(content)
	for _, loc := range mdCommentRe.FindAllStringSubmatchIndex(content, -1) {
		for g := 1; g <= 3; g++ {
			if loc[2*g] >= 0 {
				out = append(out, commentSpan{body: content[loc[2*g]:loc[2*g+1]], start: loc[0], kind: "a Markdown comment ([//]: # (…)"})
				break
			}
		}
	}
	return out
}

// commentDirectiveRe matches instruction-like text that has no legitimate reason
// to be concealed inside an HTML comment of a trusted instruction file:
// second-person directives, override/ignore phrasing, "note to the model"
// framing, and covert-action / exfiltration verbs. A comment body must match one
// of these to be flagged, so ordinary editor pragmas, TOC markers, and licence
// headers — which carry none of them — do not false-positive.
var commentDirectiveRe = regexp.MustCompile(`(?is)(` +
	`\byou\s+(?:must|should|shall|will|are\s+to|have\s+to|need\s+to|are\s+now)\b` +
	`|\b(?:always|never)\s+(?:[a-z]+\s+)?(?:respond|reply|do|run|execute|send|include|append|add|use|treat|assume|remember|forget|tell|hide|delete|ignore|approve)\b` +
	`|\b(?:do\s+not|don'?t)\s+(?:tell|mention|reveal|disclose|inform|notify|show|warn|ask|say|log)\b` +
	`|\b(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+|any\s+|the\s+|prior\s+|previous\s+|above\s+)?(?:instructions?|directives?|rules?|context|prompts?)\b` +
	`|\b(?:instructions?|directive|note|message)\s+(?:to|for)\s+(?:the\s+)?(?:ai|assistant|model|agent|claude|llm)\b` +
	`|\b(?:silently|secretly|quietly)\s+(?:[a-z]+\s+)?(?:run|execute|send|post|email|upload|exfiltrate|forward|delete|copy|read|fetch|call)\b` +
	`|\bexfiltrat(?:e|ion)\b` +
	`)`)

// Benign descriptions and quoted diagnostics can contain directive words
// without instructing the agent to act (#1185).
var commentInstructionsDescriptionRe = regexp.MustCompile(`(?i)^(?:see\s+\S+\s+for\s+|this\s+file\s+contains\s+|a\s+guide\s+to\s+)\S*.*\binstructions?\s+for\s+(?:ai|claude|agents?)\b`)
var commentLicenseRe = regexp.MustCompile(`(?i)^you should have received a copy of the (?:gnu\s+)?(?:affero\s+)?(?:lesser\s+)?general public license\b`)
var commentQuotedDiagnosticRe = regexp.MustCompile(`(?i)^[a-z][\w.-]*:\s*[^|\n]+\|\s+`)

// A diagnostic saying "you must define a field" is not an instruction to the
// agent. The exception must not hide a second instruction inside that diagnostic.
var commentCovertActionRe = regexp.MustCompile(`(?i)\b(?:ignore|disregard|override|bypass|exfiltrate|upload|send|execute|run|delete|call)\b`)

var commentImperativeRe = regexp.MustCompile(`(?i)\b(?:you\s+(?:must|should)|always\b|never\b|run\b|execute\b|delete\b|add\b|send\b|ignore\b|override\b|must\b)`)

func benignCommentProse(body string) bool {
	trimmed := strings.TrimSpace(body)
	if m := commentLicenseRe.FindStringIndex(trimmed); m != nil {
		// Exclude the standard "You should have received..." opening, but
		// inspect anything appended after the licence name for instructions.
		return !commentDirectiveRe.MatchString(trimmed[m[1]:])
	}
	if commentQuotedDiagnosticRe.MatchString(trimmed) {
		_, afterDiagnostic, _ := strings.Cut(trimmed, "|")
		return !commentCovertActionRe.MatchString(afterDiagnostic)
	}
	if !strings.ContainsAny(trimmed, ":;") && !commentImperativeRe.MatchString(trimmed) &&
		commentInstructionsDescriptionRe.MatchString(trimmed) {
		return true
	}
	return false
}

// Check scans each instruction source for HTML comments (<!-- … -->) whose body
// reads as an instruction. An HTML comment is invisible in rendered Markdown and
// easy to skim past in review, but the agent ingests the raw file as trusted
// context — so a directive hidden here is a prompt-injection channel, the
// comment-syntax sibling of CFG024's hidden-Unicode smuggling. Comments inside a
// fenced code block are ignored (a doc demonstrating the technique, not using it).
func (r *cfg080) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	for _, src := range t.instructionSources() {
		fenced := fencedLines(src.Content)
		for _, c := range commentSpans(maskInlineCode(src.Content, fenced)) {
			m := commentDirectiveRe.FindString(c.body)
			if m == "" || benignCommentProse(c.body) {
				continue
			}
			startLine := 1 + strings.Count(src.Content[:c.start], "\n")
			if fenced[startLine] {
				continue
			}
			findings = append(findings, finding.Finding{
				RuleID:   "CFG080",
				Severity: finding.Error,
				File:     src.File,
				Line:     startLine,
				Col:      columnAt(src.Content, c.start),
				Message: src.Name + " line " + strconv.Itoa(startLine) + ` hides an instruction inside ` + c.kind + `, matched "` + collapseWS(m) +
					`") — comments are invisible in rendered Markdown and easy to miss in review, but the agent reads the raw file as trusted context, so a directive concealed here is a prompt-injection vector. Remove it`,
			})
		}
	}
	return findings
}

// fencedLines returns the set of 1-based line numbers inside a fenced code block
// (including the ``` / ~~~ delimiter lines), so a rule can ignore an HTML comment
// shown as a documentation example rather than used as a live instruction.
func fencedLines(content string) map[int]bool {
	out := map[int]bool{}
	inFence := false
	for i, line := range strings.Split(content, "\n") {
		if isFenceDelimiter(line) {
			inFence = !inFence
			out[i+1] = true
			continue
		}
		if inFence {
			out[i+1] = true
		}
	}
	return out
}

// maskInlineCode blanks the inline code spans outside fenced blocks, keeping
// every offset. A comment marker in code formatting is shown, not hidden:
// "(e.g., `<!-- ignore rules -->`)" cites the trick a defensive rule refuses,
// and "contains `<!-- triage-frontend-ticket:`" names a marker to look for,
// which otherwise paired with a "-->" lines later (#873).
func maskInlineCode(content string, fenced map[int]bool) string {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if fenced[i+1] || !strings.Contains(line, "`") {
			continue
		}
		lines[i] = inlineCodeSpanRe.ReplaceAllStringFunc(line, func(s string) string {
			return strings.Repeat(" ", len(s))
		})
	}
	return strings.Join(lines, "\n")
}

// columnAt returns the 1-based column of byte offset off within its line.
func columnAt(content string, off int) int {
	nl := strings.LastIndexByte(content[:off], '\n')
	return off - nl // nl == -1 (first line) yields off+1
}

// collapseWS folds runs of whitespace (including newlines) into single spaces so a
// multi-line matched snippet renders on one line in a finding message.
func collapseWS(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
