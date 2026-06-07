package rules

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg035 struct{}

var CFG035 = &cfg035{}

func init() { All = append(All, CFG035) }

func (r *cfg035) ID() string { return "CFG035" }

// mcpInstructionPatterns match CLAUDE.md text that tries to install or trust an
// MCP server. CLAUDE.md is read as system context and Claude Code can run shell
// commands, so such an instruction can silently persist an attacker-controlled
// MCP server into the user's configuration.
var mcpInstructionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)claude\s+mcp\s+add\b`),
	regexp.MustCompile(`(?i)(?:add|install|configure|register|enable|connect)\s+(?:the\s+)?(?:mcp|model\s+context\s+protocol)\s+(?:server|tool|integration)`),
	regexp.MustCompile(`(?i)(?:alwaysAllow|trust|whitelist|allowlist)\s+.*\bmcp\b`),
	regexp.MustCompile(`(?i)\bmcp\b.*\b(?:alwaysAllow|trusted|allow\s+all)`),
}

// Check flags CLAUDE.md content that instructs the agent to configure or trust an
// MCP server. Matches inside fenced code blocks are still reported.
func (r *cfg035) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	for _, src := range t.instructionSources() {
		for i, line := range strings.Split(src.Content, "\n") {
			loc := firstMatch(mcpInstructionPatterns, line)
			if loc == nil {
				continue
			}
			lineNo := i + 1
			findings = append(findings, finding.Finding{
				RuleID:   "CFG035",
				Severity: finding.Error,
				File:     src.File,
				Line:     lineNo,
				Col:      loc[0] + 1,
				Message: src.Name + " line " + strconv.Itoa(lineNo) + " instructs the agent to configure or trust an MCP server (\"" + strings.TrimSpace(line[loc[0]:loc[1]]) +
					"\") — instruction files must not contain MCP configuration instructions; a malicious one can silently install an attacker-controlled MCP server into your config. Remove it",
			})
		}
	}
	return findings
}

// firstMatch returns the index range of the first pattern that matches s, or nil.
func firstMatch(res []*regexp.Regexp, s string) []int {
	for _, re := range res {
		if loc := re.FindStringIndex(s); loc != nil {
			return loc
		}
	}
	return nil
}
