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

// htmlCommentRe captures the body of an HTML comment, including multi-line ones
// (the (?s) flag lets `.` span newlines). Submatch 1 is the comment text.
var htmlCommentRe = regexp.MustCompile(`(?s)<!--(.*?)-->`)

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

// commentSpans returns every HTML comment and Markdown link-reference comment
// in content.
func commentSpans(content string) []commentSpan {
	var out []commentSpan
	for _, loc := range htmlCommentRe.FindAllStringSubmatchIndex(content, -1) {
		out = append(out, commentSpan{body: content[loc[2]:loc[3]], start: loc[0], kind: "an HTML comment (<!-- … -->"})
	}
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
		for _, c := range commentSpans(src.Content) {
			m := commentDirectiveRe.FindString(c.body)
			if m == "" {
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
