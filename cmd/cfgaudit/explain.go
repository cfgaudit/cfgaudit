package main

import (
	"fmt"
	"strings"

	cfgaudit "github.com/cfgaudit/cfgaudit"
)

// explainOutput implements `cfgaudit explain <RULE-ID>`: it returns the rendered
// rule documentation (or an error message) and the process exit code.
func explainOutput(args []string) (string, int) {
	if len(args) == 0 {
		return "usage: cfgaudit explain <RULE-ID>   (e.g. cfgaudit explain CFG001)\n" +
			"known rules: " + strings.Join(cfgaudit.RuleIDs(), ", ") + "\n", 2
	}
	id := strings.ToUpper(strings.TrimSpace(args[0]))
	doc, ok := cfgaudit.RuleDoc(id)
	if !ok {
		return fmt.Sprintf("cfgaudit: unknown rule %q\nknown rules: %s\n", id, strings.Join(cfgaudit.RuleIDs(), ", ")), 2
	}
	return renderRuleDoc(doc) +
		fmt.Sprintf("\nDocs: https://github.com/cfgaudit/cfgaudit/blob/main/docs/rules/%s.md\n", id), 0
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
			line = strings.TrimPrefix(strings.TrimLeft(line, "#"), " ")
			line = strings.ReplaceAll(line, "**", "")
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}
