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
		inFence, inComment := false, false
		lines := strings.Split(src.Content, "\n")
		fmEnd, descLines := frontmatterDescription(lines)
		for i, line := range lines {
			// A fence inside a blockquote ("> ```") is still a fence (#1180).
			if isFenceDelimiter(blockquoteStripRe.ReplaceAllString(line, "")) {
				inFence = !inFence
				continue
			}
			// Headings, HTML comments and a skill's frontmatter description are
			// not instructions: setup docs title a section "Register the MCP
			// server", and a description lists the trigger phrases its body
			// acts on (#1180). Table cells are kept, since a table can hold the
			// steps themselves.
			wasComment := inComment
			if strings.Contains(line, "<!--") {
				inComment = true
			}
			if strings.Contains(line, "-->") {
				inComment = false
			}
			if wasComment || inComment || strings.Contains(line, "<!--") || headingRe.MatchString(line) || (i < fmEnd && descLines[i]) {
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
				if trustedOtherNoun(line, loc) || mcpNotAnInstruction(line, loc) {
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

var (
	blockquoteStripRe = regexp.MustCompile(`^\s*(?:>\s?)+`)
	headingRe         = regexp.MustCompile(`^\s{0,3}#{1,6}\s`)
	// trustObjectAfterRe is an object of "trust ... MCP" that is not the
	// server: "Trust MCP results as the source of truth" (#1180).
	trustObjectAfterRe = regexp.MustCompile(`(?i)^\s+(?:results?|outputs?|responses?|data|docs?|documentation|answers?|replies)\b`)
	// trustedFollowerRe is the noun after "trusted" when it qualifies
	// something other than the server: "load trusted validator code".
	trustedFollowerRe = regexp.MustCompile(`(?i)^\s+(\w+)`)
	// sourcePathAfterRe is "MCP servers in <a source file>": developing the
	// server, not configuring the agent (#1180).
	sourcePathAfterRe = regexp.MustCompile("(?i)^s?\\s+in\\s+`[^`]+\\.(?:php|ts|tsx|js|mjs|cjs|py|go|rb|java|kt|cs|rs|swift)`")
	// developToolRe is "add / register / implement ... MCP tool(s)".
	developToolRe = regexp.MustCompile(`(?i)^(?:add|register|implement)\s+(?:the\s+)?(?:mcp|model\s+context\s+protocol)\s+tools?\b`)
	// linkTextRe finds markdown link text.
	linkTextRe = regexp.MustCompile(`\[[^\]]*\]\([^)]*\)`)
)

// mcpNotAnInstruction reports a CFG035 match that is about something other
// than configuring or trusting the agent's MCP servers (#1180): a trust word
// governing another noun, a trust boundary, a trusted-<word> compound, an
// allowlist of something else, developing an MCP tool or server in source
// code, or link text.
func mcpNotAnInstruction(line string, loc []int) bool {
	m := strings.ToLower(line[loc[0]:loc[1]])
	after := line[loc[1]:]
	for _, l := range linkTextRe.FindAllStringIndex(line, -1) {
		if loc[0] >= l[0] && loc[1] <= l[1] {
			return true
		}
	}
	switch {
	case strings.HasPrefix(m, "trust") && trustObjectAfterRe.MatchString(after):
		return true
	case strings.HasSuffix(m, "trusted") && strings.HasPrefix(after, "-"):
		return true // trusted-local, trusted-only
	case (strings.HasPrefix(m, "allowlist") || strings.HasPrefix(m, "whitelist")) && allowlistOfOther(m):
		return true // an allowlist of console functions ... MCP SDK
	case developToolRe.MatchString(m), sourcePathAfterRe.MatchString(after):
		return true
	}
	if strings.HasSuffix(m, "trusted") {
		if f := trustedFollowerRe.FindStringSubmatch(after); f != nil {
			switch strings.ToLower(f[1]) {
			case "server", "servers", "tool", "tools", "mcp", "integration", "integrations":
			default:
				return true // trusted validator code
			}
		}
	}
	return false
}

// allowlistOfOther reports an "allowlist of <noun> ... mcp" match whose
// object is another noun: "allowlist of console functions in the MCP SDK".
// "your allowlist of MCP servers" names the servers and is kept.
func allowlistOfOther(m string) bool {
	f := strings.Fields(m)
	if len(f) < 3 || f[1] != "of" {
		return false
	}
	for _, w := range f[2 : len(f)-1] {
		switch w {
		case "the", "your", "our", "its", "trusted", "approved":
		default:
			return true
		}
	}
	return false
}

// frontmatterDescription returns the end of a leading YAML frontmatter block
// and the lines of its description key, including a block scalar's
// continuation lines.
func frontmatterDescription(lines []string) (int, map[int]bool) {
	desc := map[int]bool{}
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "---" {
		return 0, desc
	}
	inDesc := false
	for i := 1; i < len(lines); i++ {
		l := lines[i]
		if strings.TrimSpace(l) == "---" {
			return i, desc
		}
		indented := strings.HasPrefix(l, " ") || strings.HasPrefix(l, "\t")
		switch {
		case !indented && strings.HasPrefix(strings.TrimSpace(l), "description:"):
			inDesc = true
		case !indented && strings.TrimSpace(l) != "":
			inDesc = false
		}
		if inDesc {
			desc[i] = true
		}
	}
	return 0, map[int]bool{}
}
