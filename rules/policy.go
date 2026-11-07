// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/config"
)

// UnenforceableAgent is an agent in the policy's scope that no committed
// permission file can carry a deny for. Path is what marks the agent's use in
// the repository, and Reason completes "<Name> ..." with why that is so.
// Categories limits the report to those policy categories; empty means all.
type UnenforceableAgent struct {
	Agent      string
	Name       string
	Path       string
	Reason     string
	Categories []string
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
	// unenforced is a category CFG118 reports for this agent instead of
	// CFG025 checking it.
	unenforced string
}

var policySpellings = map[string]policySpelling{
	"claude-code": {name: "Claude Code", covers: claudeCovers, overlaps: claudeOverlaps, spell: claudeSpell},
	"devin":       {name: "Devin CLI", covers: devinCovers, overlaps: devinOverlaps, spell: devinSpell},
	"cursor-cli":  {name: "Cursor CLI", covers: cursorCovers, overlaps: cursorOverlaps, spell: cursorSpell, unenforced: "fetch"},
	"qwen-code":   {name: "Qwen Code", covers: qwenCovers, overlaps: qwenOverlaps, spell: qwenSpell},
	"grok":        {name: "Grok", covers: grokCovers, overlaps: grokOverlaps, spell: grokSpell},
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

// starGlobRe compiles a pattern the way Cursor CLI does, and Grok for a command:
// anchored, every * is .* and crosses path separators, and nothing else is
// special. A pattern with a * in the value it is matched against treats that *
// as text, which only a * in the pattern can consume, so a match means the
// pattern covers every string the value stands for.
func starGlobRe(p string) *regexp.Regexp {
	return regexp.MustCompile("(?s)^" + strings.ReplaceAll(regexp.QuoteMeta(strings.TrimSpace(p)), `\*`, ".*") + "$")
}

func starGlob(p, s string) bool {
	return starGlobRe(p).MatchString(s)
}

// cursorShellArg returns the argument of a shell entry. The CLI reads Bash(...)
// as well as Shell(...), which matters for the entries it takes from
// .claude/settings.json.
func cursorShellArg(e string) (string, bool) {
	if arg, ok := toolArg(e, "Shell"); ok {
		return arg, true
	}
	return toolArg(e, "Bash")
}

// cursorShellMatches is the CLI's matchesShell for one command. Base is the
// first word and args the rest. A pattern with a colon matches command and
// args apart, and any pattern also matches the whole command, the base, or a
// word prefix.
func cursorShellMatches(pattern, command string) bool {
	base, args, _ := strings.Cut(command, " ")
	args = strings.TrimSpace(args)
	if cmd, argp, ok := strings.Cut(pattern, ":"); ok &&
		(starGlob(cmd, base) || starGlob(cmd, command)) && starGlob(argp, args) {
		return true
	}
	return starGlob(pattern, command) || strings.HasPrefix(command, pattern+" ") ||
		starGlob(pattern, base) || base == pattern
}

// cursorPathTarget is what a neutral path entry stands for in the CLI, which
// compares a pattern with the whole absolute path: a repository path has to
// match at any depth, because the CLI never resolves a pattern against the
// workspace.
func cursorPathTarget(v string) string {
	if strings.HasPrefix(v, "~/") || strings.HasPrefix(v, "**/") {
		return v
	}
	return "**/" + v
}

// cursorCovers follows the matching code of the Cursor CLI package
// (2026.11.05-86047df): Shell(...) or Bash(...), Read(glob) and Write(glob), and
// Mcp(server:tool). A path pattern such as .env* or src/** never matches,
// because the absolute path has to match the whole pattern, and a Read deny
// does not block writes. A bare git push runs past Shell(git push *), so a
// command entry has to match the command with and without arguments.
func cursorCovers(category, e, v string) bool {
	e = strings.TrimSpace(e)
	switch category {
	case "commands":
		arg, ok := cursorShellArg(e)
		return ok && cursorShellMatches(arg, v) && cursorShellMatches(arg, v+" *")
	case "read", "write":
		tool := "Read"
		if category == "write" {
			tool = "Write"
		}
		arg, ok := toolArg(e, tool)
		return ok && arg != "" && starGlob(arg, cursorPathTarget(v))
	case "mcp-tools":
		server, tool, ok := cursorMcpArg(e)
		vs, vt, _ := strings.Cut(strings.ToLower(v), ":")
		return ok && starGlob(server, vs) && starGlob(tool, vt)
	}
	return false
}

// cursorMcpArg splits an Mcp(server:tool) entry, in lower case as the CLI
// compares it.
func cursorMcpArg(e string) (server, tool string, ok bool) {
	arg, ok := toolArg(e, "Mcp")
	if !ok {
		return "", "", false
	}
	return strings.Cut(strings.ToLower(arg), ":")
}

func cursorOverlaps(category, e, v string) bool {
	e = strings.TrimSpace(e)
	switch category {
	case "commands":
		arg, ok := cursorShellArg(e)
		if !ok {
			return false
		}
		if cursorShellMatches(arg, v) || cursorShellMatches(arg, v+" *") {
			return true
		}
		// A narrower allow, Shell(git push --force) under "git push".
		literal, _, _ := strings.Cut(strings.Replace(arg, ":", " ", 1), "*")
		return hasCmdPrefix(strings.TrimSpace(literal), v)
	case "mcp-tools":
		server, tool, ok := cursorMcpArg(e)
		vs, vt, _ := strings.Cut(strings.ToLower(v), ":")
		return ok && starGlob(server, vs) && (starGlob(tool, vt) || starGlob(vt, tool))
	}
	return false
}

func cursorSpell(category, v string) string {
	switch category {
	case "commands":
		return "Shell(" + v + ")"
	case "read":
		return "Read(" + cursorPathTarget(v) + ")"
	case "write":
		return "Write(" + cursorPathTarget(v) + ")"
	default:
		return "Mcp(" + v + ")"
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
