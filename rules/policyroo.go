// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

// RooPolicy is what Roo Code keeps in a repository for the neutral policy
// (#1517): command prefixes in .vscode/settings.json, .rooignore, and the
// servers of .roo/mcp.json.
type RooPolicy struct {
	SettingsFile string
	Allowed      []string
	Denied       []string
	IgnoreFile   string
	Ignore       string
	MCPFile      string
	MCP          map[string]parser.MCPServer
}

// rooLongestPrefix is findLongestPrefixMatch: case-insensitive, with no word
// boundary, and "*" counts as one character.
func rooLongestPrefix(command string, prefixes []string) string {
	command = strings.ToLower(strings.TrimSpace(command))
	longest, found := "", false
	for _, p := range prefixes {
		p = strings.ToLower(p)
		if (p == "*" || strings.HasPrefix(command, p)) && (!found || len(p) > len(longest)) {
			longest, found = p, true
		}
	}
	return longest
}

// rooDenied reports whether a denied prefix decides the command: an allowed
// prefix that is longer wins over it, so a list is not read as a set.
func rooDenied(p *RooPolicy, command string) bool {
	denied := rooLongestPrefix(command, p.Denied)
	return denied != "" && len(rooLongestPrefix(command, p.Allowed)) <= len(denied)
}

// rooCommandCovered checks the command with and without arguments.
func rooCommandCovered(p *RooPolicy, v string) bool {
	return rooDenied(p, v) && rooDenied(p, v+" --force")
}

// rooCommandGrant returns an allowed prefix that runs something v names.
func rooCommandGrant(p *RooPolicy, v string) (string, bool) {
	for _, a := range p.Allowed {
		lower, want := strings.ToLower(strings.TrimSpace(a)), strings.ToLower(v)
		applies := lower == "*" || strings.HasPrefix(want, lower) || hasCmdPrefix(lower, want)
		if applies && !rooDenied(p, a) && !rooCommandCovered(p, v) {
			return a, true
		}
	}
	return "", false
}

// rooIgnored reports whether .rooignore, read in order like gitignore, leaves
// the path ignored. Only the forms a neutral entry can take are compared.
func rooIgnored(ignore, v string) bool {
	ignored := false
	for _, line := range strings.Split(ignore, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pattern, negated := strings.CutPrefix(line, "!")
		if rooIgnoreCovers(pattern, v) {
			ignored = !negated
		}
	}
	return ignored
}

func rooIgnoreCovers(pattern, v string) bool {
	pattern = strings.TrimPrefix(pattern, "/")
	base := strings.TrimPrefix(v, "**/")
	if pattern == v || pattern == base || "**/"+pattern == v {
		return true
	}
	dir := strings.TrimSuffix(strings.TrimSuffix(pattern, "**"), "/")
	return strings.HasPrefix(v, dir+"/")
}

// rooMCPDenied applies disabled and disabledTools. As for Codex, a server the
// file does not configure has nothing to deny.
func rooMCPDenied(servers map[string]parser.MCPServer, v string) bool {
	server, tool, _ := strings.Cut(v, ":")
	s, ok := servers[server]
	if !ok || s.Disabled {
		return true
	}
	for _, name := range s.DisabledTools {
		if name == tool {
			return true
		}
	}
	return false
}

func rooMCPGrant(servers map[string]parser.MCPServer, v string) (string, bool) {
	server, tool, _ := strings.Cut(v, ":")
	for _, name := range servers[server].AlwaysAllow {
		if name == "*" || codexToolMatch(name, tool) {
			return name, true
		}
	}
	return "", false
}

// checkRooPolicy checks the neutral policy against Roo Code. A home path and a
// fetch entry go to CFG118, since .rooignore allows what is outside the project
// and Roo Code has no rule for a domain.
func checkRooPolicy(t *Target, sp policySpelling) []finding.Finding {
	p := t.PolicyRoo
	var findings []finding.Finding
	add := func(file, msg string) {
		findings = append(findings, finding.Finding{RuleID: "CFG025", Severity: finding.Error, File: file, Message: msg})
	}
	missing := func(file, key, v, fix string) {
		add(file, "policy deny."+key+" \""+v+"\": nothing covers it, so "+sp.name+" does not block it; add "+fix)
	}
	for _, c := range policyCategories {
		for _, v := range c.entries(t.PolicyDeny) {
			switch c.key {
			case "commands":
				if !rooCommandCovered(p, v) {
					missing(p.SettingsFile, c.key, v, strconv.Quote(v)+" to roo-cline.deniedCommands, with no longer prefix in roo-cline.allowedCommands")
				}
			case "read", "write":
				if !strings.HasPrefix(v, "~/") && !rooIgnored(p.Ignore, v) {
					missing(p.IgnoreFile, c.key, v, "the line "+v+" to .rooignore")
				}
			case "mcp-tools":
				if !rooMCPDenied(p.MCP, v) {
					server, tool, _ := strings.Cut(v, ":")
					fix := strconv.Quote(tool) + " to disabledTools of " + server
					if strings.HasSuffix(tool, "*") {
						fix = "each matching tool to disabledTools of " + server
					}
					missing(p.MCPFile, c.key, v, fix)
				}
			}
		}
		for _, v := range c.entries(t.PolicyForbid) {
			switch c.key {
			case "commands":
				if a, ok := rooCommandGrant(p, v); ok {
					add(p.SettingsFile, "policy forbid-allow.commands \""+v+"\": roo-cline.allowedCommands grants it via \""+a+"\", so "+sp.name+" runs it without asking when auto-execute is on")
				}
			case "mcp-tools":
				if a, ok := rooMCPGrant(p.MCP, v); ok {
					add(p.MCPFile, "policy forbid-allow.mcp-tools \""+v+"\": alwaysAllow grants it via \""+a+"\", so "+sp.name+" runs it without asking")
				}
			}
		}
	}
	return findings
}

// checkGeminiPolicy reports a forbidden command that tools.allowed approves.
// Gemini CLI's deny side is one whole tool at a time, which CFG118 reports.
func checkGeminiPolicy(t *Target, sp policySpelling) []finding.Finding {
	var findings []finding.Finding
	for _, v := range t.PolicyForbid.Commands {
		for _, e := range t.PolicyGeminiAllowed {
			arg, whole, ok := commandEntry(strings.TrimSpace(e), "run_shell_command", "ShellTool")
			if ok && (whole || hasCmdPrefix(v, arg) || hasCmdPrefix(arg, v)) {
				findings = append(findings, finding.Finding{RuleID: "CFG025", Severity: finding.Error, File: t.PolicyFile,
					Message: "policy forbid-allow.commands \"" + v + "\": tools.allowed grants it via \"" + e + "\", so " + sp.name + " runs it without asking"})
				break
			}
		}
	}
	return findings
}
