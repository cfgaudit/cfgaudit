package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"regexp"
	"strings"

	cfgaudit "github.com/cfgaudit/cfgaudit"
)

type ruleSummary struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	OWASP       string `json:"owasp"`
	OWASPMCP    string `json:"owasp_mcp,omitempty"`
	Description string `json:"description"`
}

var (
	docTitleRe = regexp.MustCompile(`(?m)^#\s+(CFG\d{3})\s*[—-]\s*(.+?)\s*$`)
	docSevRe   = regexp.MustCompile(`(?m)^\*\*Severity:\*\*\s*(.+?)\s*$`)
	docOwaspRe = regexp.MustCompile(`LLM\d{2}`)
	docMcpRe   = regexp.MustCompile(`MCP\d{2}`)
	sevTokenRe = regexp.MustCompile("`(error|warn|info)`")
	mdInlineRe = regexp.MustCompile("`([^`]*)`")
)

// listOutput implements `cfgaudit list [--format json] [--owasp LLMxx]`,
// returning the rendered table (or JSON) and the process exit code.
func listOutput(args []string) (string, int) {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	var out strings.Builder
	fs.SetOutput(&out)
	format := fs.String("format", "text", "output format: text, json")
	owasp := fs.String("owasp", "", "filter by OWASP category — LLM (e.g. LLM06) or MCP (e.g. MCP05)")
	if err := fs.Parse(args); err != nil {
		return out.String(), 2
	}

	filter := strings.ToUpper(*owasp)
	var rules []ruleSummary
	for _, id := range cfgaudit.RuleIDs() {
		doc, ok := cfgaudit.RuleDoc(id)
		if !ok {
			continue
		}
		s := summarize(id, doc)
		if filter != "" && s.OWASP != filter && s.OWASPMCP != filter {
			continue
		}
		rules = append(rules, s)
	}

	if *format == "json" {
		b, err := json.MarshalIndent(rules, "", "  ")
		if err != nil {
			return fmt.Sprintf("cfgaudit: %v\n", err), 2
		}
		return string(b) + "\n", 0
	}
	return renderRuleTable(rules), 0
}

func summarize(id, doc string) ruleSummary {
	s := ruleSummary{ID: id}
	if m := docTitleRe.FindStringSubmatch(doc); m != nil {
		s.Description = stripInlineMarkdown(m[2])
	}
	if m := docSevRe.FindStringSubmatch(doc); m != nil {
		s.Severity = compactSeverity(m[1])
	}
	if m := docOwaspRe.FindString(doc); m != "" {
		s.OWASP = m
	}
	// Secondary, MCP-specific mapping — present only on the MCP-server rules
	// (provisional, against OWASP MCP Top 10 v0.1).
	if m := docMcpRe.FindString(doc); m != "" {
		s.OWASPMCP = m
	}
	return s
}

// compactSeverity reduces a Severity line ("`error` (project) · `info` (user)")
// to a compact form ("error/info").
func compactSeverity(line string) string {
	var seen []string
	for _, m := range sevTokenRe.FindAllStringSubmatch(line, -1) {
		if !contains(seen, m[1]) {
			seen = append(seen, m[1])
		}
	}
	if len(seen) == 0 {
		return strings.TrimSpace(stripInlineMarkdown(line))
	}
	return strings.Join(seen, "/")
}

func stripInlineMarkdown(s string) string {
	return mdInlineRe.ReplaceAllString(s, "$1")
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func renderRuleTable(rules []ruleSummary) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%-7s %-11s %-7s %-7s %s\n", "ID", "SEVERITY", "OWASP", "MCP", "DESCRIPTION")
	for _, r := range rules {
		fmt.Fprintf(&b, "%-7s %-11s %-7s %-7s %s\n", r.ID, r.Severity, r.OWASP, r.OWASPMCP, r.Description)
	}
	fmt.Fprintf(&b, "\n%d %s total\n", len(rules), pluralize("rule", len(rules)))
	return b.String()
}
