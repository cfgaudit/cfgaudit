// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

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
	re       filteredRegexp
	sev      finding.Severity
	skipCode bool
}

var mcpInstructionPatterns = []mcpInstrPattern{
	{mustFiltered(`(?i)claude\s+mcp\s+add\b`), finding.Warn, true},
	{mustFiltered(`(?i)(?:add|install|configure|register|enable|connect)\s+(?:the\s+)?(?:mcp|model\s+context\s+protocol)\s+(?:server|tool|integration)`), finding.Warn, true},
	// The trust verb and the MCP server have to be within a few words of each
	// other: with `.*` any line holding "trust"/"allowlist" and a later "MCP"
	// matched, such as "allowlist `MCP_LOGO_FETCH_HOSTS` (default: public icon
	// CDNs only ...)" (#856).
	{mustFiltered(`(?i)\b(?:alwaysAllow|trust|whitelist|allowlist)\s+(?:[\w.@/\-]+\s+){0,3}?mcp\b`), finding.Error, false},
	{mustFiltered(`(?i)\bmcp\b(?:\s+[\w.@/\-]+){0,4}?\s+(?:to\s+)?(?:alwaysAllow|(?:is\s+|are\s+|as\s+)?trusted|allow\s+all)\b`), finding.Error, false},
}

// trustedNounAfterRe matches the noun that "trusted" qualifies when it is an
// adjective of something else: "trusted interactive OS user", "trusted
// hosts".
var trustedNounAfterRe = regexp.MustCompile(`(?i)^\s+(?:[\w]+[\s-]+){0,3}?(?:users?|operators?|people|persons?|humans?|hosts?|machines?|clients?|devices?|networks?|developers?|admins?|administrators?|accounts?|part(?:y|ies))\b`)

// trustedOtherNoun reports a match that ends in "trusted" used as an adjective
// of another noun: "ae-mcp supports one trusted interactive OS user" states
// whom the product trusts, it does not tell the agent to trust a server
// (#957). "the mcp server is trusted" and "mcp as trusted" keep matching.
func trustedOtherNoun(line string, loc []int) bool {
	m := strings.ToLower(line[loc[0]:loc[1]])
	if !strings.HasSuffix(m, "trusted") {
		return false
	}
	f := strings.Fields(m)
	if len(f) >= 2 {
		switch f[len(f)-2] {
		case "is", "are", "as":
			return false
		}
	}
	return trustedNounAfterRe.MatchString(line[loc[1]:])
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
				if trustedOtherNoun(line, loc) {
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
