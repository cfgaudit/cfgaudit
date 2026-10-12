package parser

import (
	"regexp"
	"strings"
)

// Claude Code runs shell commands embedded in a skill or slash command before
// the text reaches the model (#643). Both patterns are copied from the 2.1.296
// binary, where they sit next to each other:
//
//	/```!\s*\n?([\s\S]*?)\n?```/g
//	/(?<=^|\s)!`([^`]+)`/gm
//
// RE2 has no lookbehind, so the inline form consumes the preceding whitespace
// instead of asserting it. That changes no match: a second inline command
// directly after the first's closing backtick has no whitespace before it in
// either engine.
var (
	skillShellFencedRe = regexp.MustCompile("```!\\s*\\n?([\\s\\S]*?)\\n?```")
	skillShellInlineRe = regexp.MustCompile("(?m)(?:^|\\s)!`([^`]+)`")
)

// SkillShellCommands returns the commands a skill or slash command file runs
// when it is invoked, fenced blocks first, in file order.
//
// Measured with 2.1.296 (`claude -p "/demo"`, and a model-invoked skill through
// a scripted Skill tool call): both forms run when the command is pre-approved,
// mid-line too, and also inside an ordinary ``` fence or an HTML comment, which
// is why nothing is skipped here. "word!`cmd`" (no whitespace before the bang)
// and "!``cmd``" do not run.
func SkillShellCommands(content string) []string {
	var out []string
	for _, m := range skillShellFencedRe.FindAllStringSubmatch(content, -1) {
		if cmd := strings.TrimSpace(m[1]); cmd != "" {
			out = append(out, cmd)
		}
	}
	for _, m := range skillShellInlineRe.FindAllStringSubmatch(content, -1) {
		if cmd := strings.TrimSpace(m[1]); cmd != "" {
			out = append(out, cmd)
		}
	}
	return out
}
