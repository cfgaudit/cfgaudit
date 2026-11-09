// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strings"
)

// hostCovers reports whether the domain rule e, which matches a host and its
// subdomains and takes no wildcards, blocks every domain v names. Qwen Code
// and Grok have no rule for subdomains alone, so *.d needs a rule for d.
func hostCovers(e, v string) bool {
	e, v = strings.ToLower(e), strings.TrimPrefix(strings.ToLower(v), "*.")
	return e != "" && !strings.Contains(e, "*") && (v == e || strings.HasSuffix(v, "."+e))
}

// commandEntry reports whether e names one of the shell tools, with its
// argument; a bare tool name or * blocks every command.
func commandEntry(e string, tools ...string) (arg string, whole, ok bool) {
	for _, tool := range tools {
		if e == tool {
			return "", true, true
		}
		if a, found := toolArg(e, tool); found {
			return a, a == "*" || a == "", true
		}
	}
	return "", false, false
}

// qwenCommandRe compiles a Qwen Code command pattern as matchesCommandPattern
// does: a * after a space also matches nothing, so "git push *" matches a bare
// git push, and a pattern with no * is a word prefix.
func qwenCommandRe(p string) *regexp.Regexp {
	var b strings.Builder
	parts := strings.Split(p, "*")
	for i, part := range parts {
		if i == len(parts)-1 {
			b.WriteString(regexp.QuoteMeta(part))
			break
		}
		if trimmed, ok := strings.CutSuffix(part, " "); ok {
			b.WriteString(regexp.QuoteMeta(trimmed) + "( .*)?")
		} else {
			b.WriteString(regexp.QuoteMeta(part) + ".*")
		}
	}
	return regexp.MustCompile("(?s)^" + b.String() + "$")
}

func qwenCommandMatches(p, command string) bool {
	if !strings.Contains(p, "*") {
		return hasCmdPrefix(command, p)
	}
	return qwenCommandRe(p).MatchString(command)
}

// qwenShellTools are the aliases of run_shell_command.
var qwenShellTools = []string{"Bash", "Shell", "ShellTool", "run_shell_command"}

// qwenCommandArg normalizes a command pattern: a :* becomes " *" anywhere in it.
func qwenCommandArg(arg string) string {
	return strings.ReplaceAll(arg, ":*", " *")
}

// qwenPath drops what Qwen Code resolves against the project root or the
// working directory: /src and ./src and src name the same path when the agent
// starts at the root. A leading // is an absolute path, which a repository
// entry never equals.
func qwenPath(p string) string {
	if strings.HasPrefix(p, "//") {
		return p
	}
	return strings.TrimPrefix(strings.TrimPrefix(p, "./"), "/")
}

// qwenCovers follows Qwen Code's rule-parser.ts (c2e77d1). Read is a category
// that does not reach writes, and Edit covers edit, write_file and
// notebook_edit while Write(path) covers write_file alone.
func qwenCovers(category, e, v string) bool {
	e = strings.TrimSpace(e)
	switch category {
	case "commands":
		arg, whole, ok := commandEntry(e, qwenShellTools...)
		arg = qwenCommandArg(arg)
		return ok && (whole || (qwenCommandMatches(arg, v) && qwenCommandMatches(arg, v+" *")))
	case "read", "write":
		tools := []string{"Read", "read_file", "ReadFile", "ReadFileTool"}
		if category == "write" {
			tools = []string{"Edit", "edit", "EditTool"}
		}
		arg, whole, ok := commandEntry(e, tools...)
		return ok && ((whole && arg != "*") || globCovers(qwenPath(arg), v))
	case "fetch":
		arg, whole, ok := commandEntry(e, "WebFetch", "web_fetch", "WebFetchTool")
		return ok && ((whole && arg != "*") || hostCovers(strings.TrimPrefix(arg, "domain:"), v))
	case "mcp-tools":
		return mcpCovers(e, v, true)
	}
	return false
}

// narrowerCommand reports whether a pattern, read up to its first *, names a
// command under v, as Shell(git push --force) does under "git push".
func narrowerCommand(arg, v string) bool {
	literal, _, _ := strings.Cut(arg, "*")
	return hasCmdPrefix(strings.TrimSpace(literal), v)
}

func qwenOverlaps(category, e, v string) bool {
	e = strings.TrimSpace(e)
	switch category {
	case "commands":
		arg, whole, ok := commandEntry(e, qwenShellTools...)
		if !ok {
			return false
		}
		arg = qwenCommandArg(arg)
		return whole || qwenCommandMatches(arg, v) || qwenCommandMatches(arg, v+" *") || narrowerCommand(arg, v)
	case "mcp-tools":
		return mcpOverlaps(e, v, true)
	}
	return false
}

// qwenRepoPath spells a repository path from the project root, which holds
// from any working directory.
func qwenRepoPath(v string) string {
	if strings.HasPrefix(v, "~/") || strings.HasPrefix(v, "**/") {
		return v
	}
	return "/" + v
}

func qwenSpell(category, v string) string {
	switch category {
	case "commands":
		return "Bash(" + v + ")"
	case "read":
		return "Read(" + qwenRepoPath(v) + ")"
	case "write":
		return "Edit(" + qwenRepoPath(v) + ")"
	case "fetch":
		return "WebFetch(domain:" + strings.TrimPrefix(v, "*.") + ")"
	default:
		return mcpSpell(v)
	}
}

// grokCommandMatches is a Bash pattern against a command: a word prefix, or a
// glob over the whole command in which * crosses every character.
func grokCommandMatches(p, command string) bool {
	p = strings.TrimSuffix(p, ":*")
	return hasCmdPrefix(command, p) || starGlob(p, command)
}

// grokPathTarget is what a neutral path stands for in Grok, which keeps a
// leading ~/ as literal text and so never matches it against the home
// directory: only a **/ pattern reaches those files from a committed file.
func grokPathTarget(v string) string {
	if rest, ok := strings.CutPrefix(v, "~/"); ok {
		return "**/" + rest
	}
	return v
}

// grokMcpEntry rewrites MCPTool(server__tool) onto the mcp__server__tool form.
func grokMcpEntry(e string) (entry string, whole, bareServer bool) {
	if e == "MCPTool" {
		return "", true, false
	}
	if arg, ok := toolArg(e, "MCPTool"); ok {
		return "mcp__" + arg, arg == "*" || arg == "", false
	}
	return e, false, true
}

// grokCovers follows xai-grok-permission-rules (2bdd1d6): rules.rs for parsing
// and policy.rs for matching. Edit and Write are one tool, and a Read deny does
// not reach it.
func grokCovers(category, e, v string) bool {
	e = strings.TrimSpace(e)
	switch category {
	case "commands":
		arg, whole, ok := commandEntry(e, "Bash")
		return ok && (whole || (grokCommandMatches(arg, v) && grokCommandMatches(arg, v+" *")))
	case "read", "write":
		tools := []string{"Read"}
		if category == "write" {
			tools = []string{"Edit", "Write"}
		}
		arg, whole, ok := commandEntry(e, tools...)
		return ok && (whole || globCovers(strings.TrimPrefix(arg, "./"), grokPathTarget(v)))
	case "fetch":
		arg, whole, ok := commandEntry(e, "WebFetch")
		if !ok || whole {
			return ok
		}
		domain, ok := strings.CutPrefix(arg, "domain:")
		return ok && hostCovers(strings.TrimPrefix(strings.ToLower(domain), "www."), strings.TrimPrefix(v, "www."))
	case "mcp-tools":
		entry, whole, bareServer := grokMcpEntry(e)
		return whole || mcpCovers(entry, v, bareServer)
	}
	return false
}

func grokOverlaps(category, e, v string) bool {
	e = strings.TrimSpace(e)
	switch category {
	case "commands":
		arg, whole, ok := commandEntry(e, "Bash")
		if !ok {
			return false
		}
		return whole || grokCommandMatches(arg, v) || grokCommandMatches(arg, v+" *") || narrowerCommand(strings.TrimSuffix(arg, ":*"), v)
	case "mcp-tools":
		entry, whole, bareServer := grokMcpEntry(e)
		return whole || mcpOverlaps(entry, v, bareServer)
	}
	return false
}

func grokSpell(category, v string) string {
	switch category {
	case "commands":
		return "Bash(" + v + ")"
	case "read":
		return "Read(" + grokPathTarget(v) + ")"
	case "write":
		return "Edit(" + grokPathTarget(v) + ")"
	case "fetch":
		return "WebFetch(domain:" + strings.TrimPrefix(v, "*.") + ")"
	default:
		server, tool, _ := strings.Cut(v, ":")
		return "MCPTool(" + server + "__" + tool + ")"
	}
}
