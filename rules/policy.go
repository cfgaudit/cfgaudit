// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/config"
)

// UnenforceableAgent is an agent in the policy's scope whose permission rules
// live in user-level settings only, so no committed file can carry a deny.
// Dir is the agent's directory in the repository.
type UnenforceableAgent struct {
	Agent string
	Name  string
	Dir   string
}

// policyCategory is one category of the agent-neutral policy.
type policyCategory struct {
	key     string // the key under policy.deny / policy.forbid-allow
	entries func(config.PolicyRules) []string
}

var policyCategories = []policyCategory{
	{"commands", func(r config.PolicyRules) []string { return r.Commands }},
	{"read", func(r config.PolicyRules) []string { return r.Read }},
	{"write", func(r config.PolicyRules) []string { return r.Write }},
	{"fetch", func(r config.PolicyRules) []string { return r.Fetch }},
	{"mcp-tools", func(r config.PolicyRules) []string { return r.MCPTools }},
}

// policySpelling maps the neutral policy onto one agent's permission syntax.
type policySpelling struct {
	name string
	// covers reports whether deny entry e blocks everything value v of the
	// category names.
	covers func(category, e, v string) bool
	// overlaps reports whether allow entry e grants anything v names.
	overlaps func(category, e, v string) bool
	// spell is the deny entry that blocks v, in the agent's syntax.
	spell func(category, v string) string
}

var policySpellings = map[string]policySpelling{
	"claude-code": {name: "Claude Code", covers: claudeCovers, overlaps: claudeOverlaps, spell: claudeSpell},
	"devin":       {name: "Devin CLI", covers: devinCovers, overlaps: devinOverlaps, spell: devinSpell},
}

// claudeCovers follows Claude Code's permission syntax: Bash(prefix *) or
// Bash(prefix:*) for a command family, Read and Edit globs in gitignore syntax
// (a Read deny also blocks edits of the same path), WebFetch(domain:d), and
// mcp__server, mcp__server__tool with tool-name globs. A bare tool name denies
// the whole tool.
func claudeCovers(category, e, v string) bool {
	e = strings.TrimSpace(e)
	switch category {
	case "commands":
		if e == "Bash" {
			return true
		}
		p, ok := parsePerm(e)
		return ok && covers(p, permPattern{tool: "Bash", prefix: v, wildcard: true})
	case "read", "write":
		tools := []string{"Read"}
		if category == "write" {
			tools = append(tools, "Edit")
		}
		for _, tool := range tools {
			if e == tool {
				return true
			}
			if arg, ok := toolArg(e, tool); ok && globCovers(claudeGlob(arg), claudeGlob(v)) {
				return true
			}
		}
	case "fetch":
		if e == "WebFetch" {
			return true
		}
		arg, ok := toolArg(e, "WebFetch")
		return ok && strings.HasPrefix(arg, "domain:") && domainCovers(strings.TrimPrefix(arg, "domain:"), v)
	case "mcp-tools":
		return mcpCovers(e, v, true)
	}
	return false
}

func claudeOverlaps(category, e, v string) bool {
	e = strings.TrimSpace(e)
	switch category {
	case "commands":
		if e == "Bash" {
			return true
		}
		p, ok := parsePerm(e)
		return ok && overlap(p, permPattern{tool: "Bash", prefix: v, wildcard: true})
	case "mcp-tools":
		// Claude Code skips an allow glob not anchored at mcp__<server>__, so
		// mcp__* grants nothing.
		return e != "mcp__*" && mcpOverlaps(e, v, true)
	}
	return false
}

func claudeSpell(category, v string) string {
	switch category {
	case "commands":
		return "Bash(" + v + " *)"
	case "read":
		return "Read(" + v + ")"
	case "write":
		return "Edit(" + v + ")"
	case "fetch":
		return "WebFetch(domain:" + v + ")"
	default:
		return mcpSpell(v)
	}
}

// devinCovers follows Devin CLI's permission syntax: Exec(prefix) matching
// whole words, Read(glob) and Write(glob), Fetch(domain:d) for one exact
// domain or Fetch(https://host/*) as a URL pattern, mcp__server__tool,
// mcp__server__* and mcp__*, and the bare tool names exec, read and edit.
func devinCovers(category, e, v string) bool {
	e = strings.TrimSpace(e)
	switch category {
	case "commands":
		if e == "exec" {
			return true
		}
		arg, ok := toolArg(e, "Exec")
		return ok && hasCmdPrefix(v, arg)
	case "read":
		if e == "read" {
			return true
		}
		arg, ok := toolArg(e, "Read")
		return ok && globCovers(arg, v)
	case "write":
		if e == "edit" {
			return true
		}
		arg, ok := toolArg(e, "Write")
		return ok && globCovers(arg, v)
	case "fetch":
		arg, ok := toolArg(e, "Fetch")
		if !ok {
			return false
		}
		// Devin documents domain: for one exact domain only.
		if d, ok := strings.CutPrefix(arg, "domain:"); ok {
			return d == v && !strings.Contains(d, "*")
		}
		host, ok := strings.CutPrefix(arg, "https://")
		if !ok {
			return false
		}
		host, ok = strings.CutSuffix(host, "/*")
		return ok && domainCovers(host, v)
	case "mcp-tools":
		return mcpCovers(e, v, false)
	}
	return false
}

func devinOverlaps(category, e, v string) bool {
	e = strings.TrimSpace(e)
	switch category {
	case "commands":
		if e == "exec" {
			return true
		}
		arg, ok := toolArg(e, "Exec")
		return ok && (hasCmdPrefix(v, arg) || hasCmdPrefix(arg, v))
	case "mcp-tools":
		return mcpOverlaps(e, v, false)
	}
	return false
}

func devinSpell(category, v string) string {
	switch category {
	case "commands":
		return "Exec(" + v + ")"
	case "read":
		return "Read(" + v + ")"
	case "write":
		return "Write(" + v + ")"
	case "fetch":
		if strings.HasPrefix(v, "*.") {
			return "Fetch(https://" + v + "/*)"
		}
		return "Fetch(domain:" + v + ")"
	default:
		return mcpSpell(v)
	}
}

// toolArg returns the argument of a Tool(arg) entry.
func toolArg(e, tool string) (string, bool) {
	rest, ok := strings.CutPrefix(e, tool+"(")
	if !ok {
		return "", false
	}
	rest, ok = strings.CutSuffix(rest, ")")
	return strings.TrimSpace(rest), ok
}

// claudeGlob normalizes a Claude Code path pattern: a pattern without a slash
// matches at any depth in gitignore syntax, so .env means **/.env, and a
// leading ./ means the current directory.
func claudeGlob(p string) string {
	p = strings.TrimPrefix(p, "./")
	if !strings.Contains(p, "/") {
		return "**/" + p
	}
	return p
}

// globCovers reports whether glob e matches every path glob v matches, for
// the cases decidable from the strings: equal patterns, ** for every path
// under the directory, and dir/** for every path below dir. A home-relative
// pattern is never under a repository-relative one.
func globCovers(e, v string) bool {
	if e == v {
		return true
	}
	if e == "**" || e == "**/*" {
		return !strings.HasPrefix(v, "~/")
	}
	dir, ok := strings.CutSuffix(e, "/**")
	return ok && strings.HasPrefix(v, dir+"/")
}

// domainCovers reports whether domain pattern e matches every domain v names.
// *.d matches subdomains at any depth but not d itself; * matches all.
func domainCovers(e, v string) bool {
	if e == v || e == "*" {
		return true
	}
	parent, ok := strings.CutPrefix(e, "*.")
	if !ok {
		return false
	}
	return strings.HasSuffix(strings.TrimPrefix(v, "*."), "."+parent)
}

// mcpServerName is the server segment of an MCP permission entry: Claude Code
// writes a dot or a space in a server name as an underscore.
func mcpServerName(s string) string {
	return strings.NewReplacer(".", "_", " ", "_").Replace(s)
}

func mcpSpell(v string) string {
	server, tool, _ := strings.Cut(v, ":")
	return "mcp__" + mcpServerName(server) + "__" + tool
}

// mcpEntry splits an mcp__server__tool entry; tool is "" for mcp__server.
// all is true for mcp__*.
func mcpEntry(e string) (server, tool string, all, ok bool) {
	rest, ok := strings.CutPrefix(e, "mcp__")
	if !ok || strings.ContainsAny(rest, "()") {
		return "", "", false, false
	}
	if rest == "*" {
		return "", "", true, true
	}
	server, tool, _ = strings.Cut(rest, "__")
	return server, tool, false, server != ""
}

// mcpCovers reports whether entry e blocks every tool v (server:tool) names.
// bareServer is whether mcp__server alone names the whole server.
func mcpCovers(e, v string, bareServer bool) bool {
	server, tool, all, ok := mcpEntry(e)
	if !ok {
		return false
	}
	if all {
		return true
	}
	vs, vt, _ := strings.Cut(v, ":")
	if server != mcpServerName(vs) {
		return false
	}
	if tool == "" {
		return bareServer
	}
	if tool == vt || tool == "*" {
		return true
	}
	prefix, ok := strings.CutSuffix(tool, "*")
	return ok && strings.HasPrefix(strings.TrimSuffix(vt, "*"), prefix)
}

// mcpOverlaps reports whether allow entry e grants any tool v names.
func mcpOverlaps(e, v string, bareServer bool) bool {
	server, tool, all, ok := mcpEntry(e)
	if !ok {
		return false
	}
	if all {
		return true
	}
	vs, vt, _ := strings.Cut(v, ":")
	if server != mcpServerName(vs) {
		return false
	}
	if tool == "" {
		return bareServer
	}
	ep, eGlob := strings.CutSuffix(tool, "*")
	vp, vGlob := strings.CutSuffix(vt, "*")
	switch {
	case eGlob && vGlob:
		return strings.HasPrefix(ep, vp) || strings.HasPrefix(vp, ep)
	case eGlob:
		return strings.HasPrefix(vt, ep)
	case vGlob:
		return strings.HasPrefix(tool, vp)
	default:
		return tool == vt
	}
}
