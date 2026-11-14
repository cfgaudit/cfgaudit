// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path"
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

// Kimi Code 2.6 resolves [[permission.rules]] from the user's config and the
// project's .kimi-code/local.toml (#1731): deny rules first, then the
// dangerous-command guard, ask rules and allow rules
// (agentPermissionPolicyService, user-configured-rule.ts). A pattern is "Tool"
// or "Tool(arg)"; the tool name is a picomatch glob, and each tool matches the
// argument itself (tool/rule-match.ts): Bash and FetchURL with picomatch on
// the command or URL, Read, Write and Edit with picomatch on the path and its
// variants. An MCP tool takes no argument pattern.

// kimiRepo and kimiHome stand for the workspace and the home directory when a
// path pattern is resolved, as Kimi resolves it against the real ones.
const (
	kimiRepo = "/repo"
	kimiHome = "/home/u"
)

// kimiGlob is picomatch.isMatch with its default options, as Kimi calls it:
// * and ? never cross a slash, ** as a whole segment spans segments, a
// segment starting with a dot is matched only by a pattern segment that
// starts with a literal dot, and {a,b} expands. nocase is the path option.
// An extglob (!(…), @(…), …) is not modelled and matches nothing.
func kimiGlob(value, pattern string, nocase bool) bool {
	if kimiExtglobRe.MatchString(pattern) {
		return false
	}
	if nocase {
		value, pattern = strings.ToLower(value), strings.ToLower(pattern)
	}
	vals := strings.Split(value, "/")
	for _, alt := range expandBraces(pattern) {
		if kimiSegments(strings.Split(alt, "/"), vals) {
			return true
		}
	}
	return false
}

var kimiExtglobRe = regexp.MustCompile(`[!@*+?]\(`)

// expandBraces expands the first top-level {a,b} of p, recursively. A brace
// without a comma, or without its closing brace, is literal.
func expandBraces(p string) []string {
	depth, open := 0, -1
	var commas []int
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case '\\':
			i++
		case '{':
			if depth == 0 {
				open, commas = i, nil
			}
			depth++
		case ',':
			if depth == 1 {
				commas = append(commas, i)
			}
		case '}':
			if depth == 0 {
				continue
			}
			depth--
			if depth == 0 && len(commas) > 0 {
				var out []string
				start := open + 1
				for _, c := range append(commas, i) {
					out = append(out, expandBraces(p[:open]+p[start:c]+p[i+1:])...)
					start = c + 1
				}
				return out
			}
		}
	}
	return []string{p}
}

// kimiSegments matches pattern segments against value segments. A ** spans
// any segments, empty ones included, but none that starts with a dot. A
// trailing /** may match nothing only after a literal segment: picomatch
// matches "foo" with foo/** but not "ab" with a*/**.
func kimiSegments(pats, vals []string) bool {
	return kimiSegmentsAfter(pats, vals, true)
}

func kimiSegmentsAfter(pats, vals []string, prevLiteral bool) bool {
	if len(pats) == 0 {
		return len(vals) == 0
	}
	if pats[0] == "**" {
		least := 0
		if len(pats) == 1 && !prevLiteral {
			least = 1
		}
		for n := 0; n <= len(vals); n++ {
			if n > 0 && strings.HasPrefix(vals[n-1], ".") {
				return false
			}
			if n >= least && kimiSegmentsAfter(pats[1:], vals[n:], false) {
				return true
			}
		}
		return false
	}
	literal := !strings.ContainsAny(pats[0][len(pats[0])-min(len(pats[0]), 1):], "*?]")
	return len(vals) > 0 && kimiSegment(pats[0], vals[0]) && kimiSegmentsAfter(pats[1:], vals[1:], literal)
}

// kimiSegment matches one segment: *, ?, [class], \escape, literal. A value
// starting with a dot needs a pattern starting with a literal dot.
func kimiSegment(pat, val string) bool {
	if strings.HasPrefix(val, ".") && !strings.HasPrefix(pat, ".") && !strings.HasPrefix(pat, `\.`) {
		return false
	}
	return kimiWild(pat, val)
}

func kimiWild(pat, val string) bool {
	for len(pat) > 0 {
		switch pat[0] {
		case '*':
			for len(pat) > 0 && pat[0] == '*' {
				pat = pat[1:]
			}
			for i := 0; i <= len(val); i++ {
				if kimiWild(pat, val[i:]) {
					return true
				}
			}
			return false
		case '?':
			if val == "" {
				return false
			}
			pat, val = pat[1:], val[1:]
		case '[':
			end := strings.IndexByte(pat[1:], ']')
			if end < 0 || val == "" {
				if val == "" || val[0] != '[' {
					return false
				}
				pat, val = pat[1:], val[1:]
				continue
			}
			class := pat[1 : end+1]
			// picomatch negates with ^ only; [!x] holds ! and x.
			neg := strings.HasPrefix(class, "^")
			if neg {
				class = class[1:]
			}
			if kimiInClass(class, val[0]) == neg {
				return false
			}
			pat, val = pat[end+2:], val[1:]
		case '\\':
			if len(pat) < 2 || val == "" || val[0] != pat[1] {
				return false
			}
			pat, val = pat[2:], val[1:]
		default:
			if val == "" || val[0] != pat[0] {
				return false
			}
			pat, val = pat[1:], val[1:]
		}
	}
	return val == ""
}

func kimiInClass(class string, c byte) bool {
	for i := 0; i < len(class); i++ {
		if i+2 < len(class) && class[i+1] == '-' {
			if class[i] <= c && c <= class[i+2] {
				return true
			}
			i += 2
			continue
		}
		if class[i] == c {
			return true
		}
	}
	return false
}

// kimiGlobMatch is globMatch from rule-match.ts: a leading ./ is ignored on
// either side.
func kimiGlobMatch(value, pattern string, nocase bool) bool {
	if kimiGlob(value, pattern, nocase) {
		return true
	}
	v, p := strings.TrimPrefix(value, "./"), strings.TrimPrefix(pattern, "./")
	return (v != value || p != pattern) && kimiGlob(v, p, nocase)
}

// kimiPathMatch is pathGlobMatch: the value and the pattern as written, without
// a leading ./, and resolved against the workspace and the home directory.
// Paths compare without case.
func kimiPathMatch(value, pattern string) bool {
	if kimiGlobMatch(value, pattern, true) {
		return true
	}
	for _, v := range kimiPathVariants(value) {
		for _, p := range kimiPathVariants(pattern) {
			if kimiGlobMatch(v, p, true) {
				return true
			}
		}
	}
	return false
}

func kimiPathVariants(s string) []string {
	out := []string{s, strings.TrimPrefix(s, "./")}
	expanded := s
	switch {
	case s == "~":
		expanded = kimiHome
	case strings.HasPrefix(s, "~/"):
		expanded = kimiHome + "/" + s[2:]
	}
	if !strings.HasPrefix(expanded, "/") {
		expanded = kimiRepo + "/" + expanded
	}
	return append(out, path.Clean(expanded))
}

// kimiRuleMatches is matchPermissionRule for a call of tool with subject; a
// tool without an argument matcher has an empty subject and pathArg false.
func kimiRuleMatches(pattern, tool, subject string, pathArg bool) bool {
	pattern = strings.TrimSpace(pattern)
	name, arg := pattern, ""
	if open := strings.IndexByte(pattern, '('); open >= 0 {
		if !strings.HasSuffix(pattern, ")") || open == 0 {
			return false
		}
		name, arg = pattern[:open], pattern[open+1:len(pattern)-1]
	}
	if name != "*" && !kimiGlob(tool, name, false) {
		return false
	}
	if arg == "" {
		return true
	}
	if subject == "" {
		return false // no matchesRule: an argument pattern never matches
	}
	negated := strings.HasPrefix(arg, "!")
	arg = strings.TrimPrefix(arg, "!")
	var hit bool
	if pathArg {
		hit = kimiPathMatch(subject, arg)
	} else {
		hit = kimiGlobMatch(subject, arg, false)
	}
	return hit != negated
}

// kimiCall is one concrete tool call a policy entry stands for.
type kimiCall struct {
	tool, subject string
	path          bool
}

// kimiProbes returns the calls a neutral entry stands for. A write needs both
// Write and Edit refused.
func kimiProbes(category, v string) []kimiCall {
	var calls []kimiCall
	switch category {
	case "commands":
		for _, c := range []string{v, v + " origin main", v + " --force", v + " origin feature/x"} {
			calls = append(calls, kimiCall{"Bash", c, false})
		}
	case "read", "write":
		tools := []string{"Read"}
		if category == "write" {
			tools = []string{"Write", "Edit"}
		}
		for _, tool := range tools {
			for _, p := range kimiPathProbes(v) {
				calls = append(calls, kimiCall{tool, p, true})
			}
		}
	case "fetch":
		host := strings.Replace(v, "*.", "api.", 1)
		for _, u := range []string{"https://" + host + "/x", "http://" + host + "/x", "https://" + host + "/a/b"} {
			calls = append(calls, kimiCall{"FetchURL", u, false})
		}
	case "mcp-tools":
		server, tool, _ := strings.Cut(v, ":")
		calls = append(calls, kimiCall{"mcp__" + kimiMCPName(server) + "__" + kimiMCPName(strings.ReplaceAll(tool, "*", "probe")), "", false})
	}
	return calls
}

// kimiMCPName is sanitizeMcpNamePart from mcpCore/tool-naming.ts.
func kimiMCPName(s string) string {
	return kimiMCPRunRe.ReplaceAllString(kimiMCPCharRe.ReplaceAllString(s, "_"), "_")
}

var (
	kimiMCPCharRe = regexp.MustCompile(`[^a-zA-Z0-9_-]`)
	kimiMCPRunRe  = regexp.MustCompile(`_+`)
)

// kimiPathProbes returns absolute paths a neutral path entry stands for.
func kimiPathProbes(v string) []string {
	base := kimiRepo + "/"
	if rest, ok := strings.CutPrefix(v, "~/"); ok {
		base, v = kimiHome+"/", rest
	}
	fill := func(s string) string { return strings.ReplaceAll(strings.ReplaceAll(s, "**", "probe"), "*", "probe") }
	if rest, ok := strings.CutPrefix(v, "**/"); ok {
		return []string{base + fill(rest), base + "a/" + fill(rest), base + "a/b/" + fill(rest)}
	}
	if dir, ok := strings.CutSuffix(v, "/**"); ok {
		return []string{base + dir + "/probe", base + dir + "/a/probe"}
	}
	return []string{base + fill(v)}
}

// kimiShow writes a probe path as the user would: relative to the
// repository, or under ~/.
func kimiShow(s string) string {
	if rest, ok := strings.CutPrefix(s, kimiRepo+"/"); ok {
		return rest
	}
	if rest, ok := strings.CutPrefix(s, kimiHome+"/"); ok {
		return "~/" + rest
	}
	return s
}

// kimiSpell is the rule that refuses everything v stands for.
func kimiSpell(category, v string) string {
	switch category {
	case "commands":
		return "Bash(" + kimiEscape(v) + "{, *, */**})"
	case "read":
		return "Read(" + v + ")"
	case "write":
		return "{Write,Edit}(" + v + ")"
	case "fetch":
		return "FetchURL(*://" + v + "/**)"
	}
	server, tool, _ := strings.Cut(v, ":")
	return "mcp__" + kimiMCPName(server) + "__" + tool
}

var kimiGlobSpecialRe = regexp.MustCompile(`[\\*?\[\]{}()!+@|]`)

// kimiEscape is escapeRuleSubjectLiteral: a command written as a literal.
func kimiEscape(s string) string {
	return kimiGlobSpecialRe.ReplaceAllString(s, `\$0`)
}

// kimiDecides returns the first rule of decision that matches call.
func kimiDecides(rules []parser.KimiPermissionRule, decision string, call kimiCall) (parser.KimiPermissionRule, bool) {
	for _, r := range rules {
		if r.Decision == decision && kimiRuleMatches(r.Pattern, call.tool, call.subject, call.path) {
			return r, true
		}
	}
	return parser.KimiPermissionRule{}, false
}

// kimiAllows returns an allow rule that approves something v stands for, past
// the deny rules Kimi checks first. A narrower Bash allow under v counts too.
func kimiAllows(rules []parser.KimiPermissionRule, category, v string) (parser.KimiPermissionRule, bool) {
	for _, call := range kimiProbes(category, v) {
		if _, denied := kimiDecides(rules, "deny", call); denied {
			continue
		}
		if r, ok := kimiDecides(rules, "allow", call); ok {
			return r, true
		}
	}
	if category != "commands" {
		return parser.KimiPermissionRule{}, false
	}
	for _, r := range rules {
		arg, ok := toolArg(strings.TrimSpace(r.Pattern), "Bash")
		if r.Decision != "allow" || !ok {
			continue
		}
		literal := arg
		if i := strings.IndexAny(arg, "*?[{"); i >= 0 {
			literal = arg[:i]
		}
		if strings.HasPrefix(literal, v+" ") {
			if _, denied := kimiDecides(rules, "deny", kimiCall{"Bash", literal, false}); !denied {
				return r, true
			}
		}
	}
	return parser.KimiPermissionRule{}, false
}

// checkKimiPolicy checks the neutral policy against .kimi-code/local.toml.
func checkKimiPolicy(t *Target, sp policySpelling) []finding.Finding {
	var findings []finding.Finding
	add := func(msg string) {
		findings = append(findings, finding.Finding{RuleID: "CFG025", Severity: finding.Error, File: t.PolicyFile, Message: msg})
	}
	for _, c := range policyCategories {
		for _, v := range c.entries(t.PolicyDeny) {
			for _, call := range kimiProbes(c.key, v) {
				if _, ok := kimiDecides(t.PolicyKimiRules, "deny", call); !ok {
					add("policy deny." + c.key + " \"" + v + "\": no deny rule in [[permission.rules]] matches " + call.tool + " on \"" + kimiShow(call.subject) +
						"\", so " + sp.name + " does not block it; add decision = \"deny\", pattern = \"" + kimiSpell(c.key, v) + "\"")
					break
				}
			}
		}
		for _, v := range c.entries(t.PolicyForbid) {
			if r, ok := kimiAllows(t.PolicyKimiRules, c.key, v); ok {
				add("policy forbid-allow." + c.key + " \"" + v + "\": the allow rule \"" + r.Pattern + "\" approves it, so " + sp.name + " runs it without asking")
			}
		}
	}
	return findings
}

// KimiLocalIgnored reports whether the project's .gitignore keeps
// .kimi-code/local.toml out of Git, as the vendor docs recommend. Such a file
// is the scanning user's own, not a rule the repository commits.
func KimiLocalIgnored(gitignore []byte) bool {
	rules := parseGitignoreRules(gitignore)
	return isGitignored(rules, ".kimi-code/local.toml") || isGitignored(rules, ".kimi-code")
}
