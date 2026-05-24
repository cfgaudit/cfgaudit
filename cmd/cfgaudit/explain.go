package main

import (
	"fmt"
	"io"
	"strings"

	cfgaudit "github.com/cfgaudit/cfgaudit"
)

// runExplain implements `cfgaudit explain <RULE-ID>`: it renders the rule's
// embedded documentation in a terminal-friendly form. Returns the exit code.
func runExplain(w io.Writer, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(w, "usage: cfgaudit explain <RULE-ID>   (e.g. cfgaudit explain CFG001)")
		fmt.Fprintln(w, "known rules: "+strings.Join(cfgaudit.RuleIDs(), ", "))
		return 2
	}
	id := strings.ToUpper(strings.TrimSpace(args[0]))
	doc, ok := cfgaudit.RuleDoc(id)
	if !ok {
		fmt.Fprintf(w, "cfgaudit: unknown rule %q\n", id)
		fmt.Fprintln(w, "known rules: "+strings.Join(cfgaudit.RuleIDs(), ", "))
		return 2
	}
	fmt.Fprint(w, renderRuleDoc(doc))
	fmt.Fprintf(w, "\nDocs: https://github.com/cfgaudit/cfgaudit/blob/main/docs/rules/%s.md\n", id)
	return 0
}

// renderRuleDoc converts the rule Markdown to plain terminal text: it drops
// heading markers and bold markers while leaving tables, lists, and code blocks
// readable as-is. A full Markdown renderer would be overkill (and a dependency).
func renderRuleDoc(md string) string {
	var b strings.Builder
	inFence := false
	for _, line := range strings.Split(md, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			inFence = !inFence
			b.WriteString(line + "\n")
			continue
		}
		if !inFence {
			line = strings.TrimLeft(line, "#")
			line = strings.TrimPrefix(line, " ")
			line = strings.ReplaceAll(line, "**", "")
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}
