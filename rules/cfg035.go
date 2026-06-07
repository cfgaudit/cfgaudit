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

// mcpInstrPattern matches instruction-file text that installs or trusts an MCP
// server. Trust/allow-all forms are unambiguous injection (error). The add/install
// forms — including the `claude mcp add` CLI command — are documentation-prone:
// setup skills legitimately show them, so they are warn and are skipped inside a
// fenced/inline code block (a documented command example, not an instruction).
type mcpInstrPattern struct {
	re       *regexp.Regexp
	sev      finding.Severity
	skipCode bool
}

var mcpInstructionPatterns = []mcpInstrPattern{
	{regexp.MustCompile(`(?i)claude\s+mcp\s+add\b`), finding.Warn, true},
	{regexp.MustCompile(`(?i)(?:add|install|configure|register|enable|connect)\s+(?:the\s+)?(?:mcp|model\s+context\s+protocol)\s+(?:server|tool|integration)`), finding.Warn, true},
	{regexp.MustCompile(`(?i)(?:alwaysAllow|trust|whitelist|allowlist)\s+.*\bmcp\b`), finding.Error, false},
	{regexp.MustCompile(`(?i)\bmcp\b.*\b(?:alwaysAllow|trusted|allow\s+all)`), finding.Error, false},
}

// Check flags instruction-file content that installs or trusts an MCP server. A
// trust/allow-all instruction is an error; an add/install instruction (e.g.
// `claude mcp add`) is a warn and is skipped inside code blocks, where it is a
// documented setup command rather than an injection.
func (r *cfg035) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	for _, src := range t.instructionSources() {
		inFence := false
		for i, line := range strings.Split(src.Content, "\n") {
			if isFenceDelimiter(line) {
				inFence = !inFence
				continue
			}
			for _, p := range mcpInstructionPatterns {
				if p.skipCode && inFence {
					continue
				}
				loc := p.re.FindStringIndex(line)
				if loc == nil {
					continue
				}
				if p.skipCode && inInlineCode(line, loc[0]) {
					continue
				}
				lineNo := i + 1
				findings = append(findings, finding.Finding{
					RuleID:   "CFG035",
					Severity: p.sev,
					File:     src.File,
					Line:     lineNo,
					Col:      loc[0] + 1,
					Message: src.Name + " line " + strconv.Itoa(lineNo) + " instructs the agent to configure or trust an MCP server (\"" + strings.TrimSpace(line[loc[0]:loc[1]]) +
						"\") — instruction files should not contain MCP configuration/trust instructions; a malicious one can silently install or trust an attacker-controlled MCP server. Review or remove it",
				})
				break // one finding per line
			}
		}
	}
	return findings
}
