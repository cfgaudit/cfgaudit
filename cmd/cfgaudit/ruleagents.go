// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"regexp"
	"sort"
	"strings"
)

// knownAgents are the agent slugs a rule doc's "**Agents:**" line may name
// (#1036), with the product name each stands for. A slug matches the
// "agent: <slug>" issue label where one exists. Add a slug here before a doc
// uses it; the list test rejects any other.
var knownAgents = map[string]string{
	"amp":           "Amp",
	"claude-code":   "Claude Code",
	"cline":         "Cline",
	"codex":         "OpenAI Codex CLI",
	"continue":      "Continue",
	"copilot":       "GitHub Copilot",
	"crush":         "Crush",
	"cursor":        "Cursor",
	"devin":         "Devin CLI",
	"devin-desktop": "Devin Desktop (formerly Windsurf)",
	"gemini-cli":    "Gemini CLI",
	"goose":         "goose",
	"grok":          "xAI Grok CLI",
	"kimi-cli":      "Kimi CLI",
	"kimi-code":     "Kimi Code",
	"openhands":     "OpenHands",
	"opencode":      "OpenCode",
	"qwen-code":     "qwen-code",
	"roo-code":      "Roo Code",
	"vscode":        "VS Code",
	"zed":           "Zed",
}

var docAgentsRe = regexp.MustCompile(`(?m)^\*\*Agents:\*\*\s*(.*?)\s*$`)

// docAgents returns the slugs on a rule doc's "**Agents:**" line, sorted and
// without duplicates, and whether the doc has the line at all.
func docAgents(doc string) ([]string, bool) {
	m := docAgentsRe.FindStringSubmatch(doc)
	if m == nil {
		return []string{}, false
	}
	seen := map[string]bool{}
	out := []string{}
	for _, a := range strings.Split(m[1], ",") {
		a = strings.ToLower(strings.TrimSpace(stripInlineMarkdown(a)))
		if a != "" && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	sort.Strings(out)
	return out, true
}
