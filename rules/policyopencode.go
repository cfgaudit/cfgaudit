// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

// orderedRule aliases the flattened rule of an OpenCode or Kilo Code block.
type orderedRule = parser.OpenCodePermissionRule

// orderedWildcard is Wildcard.match from OpenCode and Kilo Code: anchored, * is
// any characters, ? is one, and a trailing " *" also matches nothing, so
// "git push *" matches a bare git push. A pattern without * is exact.
func orderedWildcard(input, pattern string) bool {
	input = strings.ReplaceAll(input, `\`, "/")
	var b strings.Builder
	for _, r := range strings.ReplaceAll(pattern, `\`, "/") {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	re := b.String()
	if trimmed, ok := strings.CutSuffix(re, " .*"); ok {
		re = trimmed + "( .*)?"
	}
	return regexp.MustCompile("(?s)^" + re + "$").MatchString(input)
}

// orderedHome writes $HOME as ~, as both agents expand them to the same path.
func orderedHome(s string) string {
	if rest, ok := strings.CutPrefix(s, "$HOME"); ok {
		return "~" + rest
	}
	return s
}

// resolveOrdered is evaluate from permission.ts: the last rule that matches
// wins, in file order, not a strongest-first set. ok is false when none does.
func resolveOrdered(rules []orderedRule, action, resource string) (orderedRule, bool) {
	for i := len(rules) - 1; i >= 0; i-- {
		r := rules[i]
		if orderedWildcard(action, r.Action) && orderedWildcard(resource, orderedHome(r.Resource)) {
			return r, true
		}
	}
	return orderedRule{}, false
}

// orderedPath splits a neutral path entry into what a tool asks for: a path
// outside the project goes through external_directory, with the directory's
// glob as the resource, and a repository path is relative to the worktree.
func orderedPath(v string) (home bool, paths []string) {
	const probe = "probe"
	if strings.HasPrefix(v, "~/") {
		dir, _, _ := strings.Cut(v, "*")
		return true, []string{strings.TrimSuffix(dir, "/") + "/*"}
	}
	fill := func(s string) string { return strings.ReplaceAll(strings.ReplaceAll(s, "**", probe), "*", probe) }
	if rest, ok := strings.CutPrefix(v, "**/"); ok {
		return false, []string{fill(rest), "a/" + fill(rest), "a/b/" + fill(rest)}
	}
	if dir, ok := strings.CutSuffix(v, "/**"); ok {
		return false, []string{dir + "/" + probe, dir + "/a/" + probe}
	}
	return false, []string{fill(v)}
}

// orderedProbes returns the permission action and the concrete requests a
// neutral entry stands for. Rule lists decide by order, so the entry is checked
// by asking what these requests resolve to.
func orderedProbes(category, v string, urls bool) (action string, resources []string) {
	switch category {
	case "commands":
		return "bash", []string{v, v + " origin main", v + " --force"}
	case "read", "write":
		home, paths := orderedPath(v)
		switch {
		case home:
			return "external_directory", paths
		case category == "read":
			return "read", paths
		}
		return "edit", paths
	case "fetch":
		if !urls {
			return "webfetch", []string{"*"}
		}
		host := strings.Replace(v, "*.", "api.", 1)
		return "webfetch", []string{"https://" + host + "/x", "http://" + host + "/x"}
	}
	server, tool, _ := strings.Cut(v, ":")
	return orderedMCPName(server, tool), []string{"*"}
}

var orderedNameRe = regexp.MustCompile(`[^a-zA-Z0-9_-]`)

// orderedMCPName is the permission action of an MCP tool: server_tool, with a
// * of the neutral entry standing for a tool name.
func orderedMCPName(server, tool string) string {
	return orderedNameRe.ReplaceAllString(server, "_") + "_" + strings.ReplaceAll(tool, "*", "probe")
}

// orderedSpell is the rule that blocks v, with the key it goes under.
func orderedSpell(category, v string, urls bool) string {
	action, _ := orderedProbes(category, v, urls)
	switch {
	case category == "mcp-tools":
		server, tool, _ := strings.Cut(v, ":")
		return `"` + orderedNameRe.ReplaceAllString(server, "_") + "_" + tool + `": "deny"`
	case category == "commands":
		return `"` + v + ` *": "deny" under "bash"`
	case category == "fetch":
		return `"*://` + v + `/*": "deny" under "webfetch"`
	case strings.HasPrefix(v, "~/"):
		return `"` + v + `": "deny" under "external_directory"`
	}
	pattern := strings.ReplaceAll(strings.TrimPrefix(v, "**/"), "**", "*")
	if strings.HasPrefix(v, "**/") {
		pattern = "*" + pattern
	}
	return `"` + pattern + `": "deny" under "` + action + `"`
}

// orderedDenied reports whether every request v stands for resolves to deny.
func orderedDenied(rules []orderedRule, category, v string, urls bool) bool {
	action, resources := orderedProbes(category, v, urls)
	for _, res := range resources {
		if r, ok := resolveOrdered(rules, action, res); !ok || r.Effect != "deny" {
			return false
		}
	}
	return true
}

// orderedGrant returns a rule that lets something v names run without asking.
func orderedGrant(rules []orderedRule, category, v string, urls bool) (orderedRule, bool) {
	action, resources := orderedProbes(category, v, urls)
	for _, res := range resources {
		if r, ok := resolveOrdered(rules, action, res); ok && r.Effect == "allow" {
			return r, true
		}
	}
	// A narrower allow, "git push --force" under "git push", or
	// "github_get_*" under "github:*".
	for _, r := range rules {
		if r.Effect != "allow" {
			continue
		}
		switch {
		case category == "commands" && orderedWildcard(action, r.Action) && narrowerCommand(r.Resource, v):
			if last, ok := resolveOrdered(rules, action, r.Resource); ok && last.Effect == "allow" {
				return r, true
			}
		case category == "mcp-tools":
			server, tool, _ := strings.Cut(v, ":")
			prefix := orderedNameRe.ReplaceAllString(server, "_") + "_" + strings.TrimSuffix(tool, "*")
			if strings.HasPrefix(r.Action, prefix) {
				return r, true
			}
		}
	}
	return orderedRule{}, false
}

// OrderedDeniesFetch reports whether the blocks switch the fetch tool off,
// the only way OpenCode can honour a domain entry.
func OrderedDeniesFetch(blocks []parser.OpenCodePermissionBlock) bool {
	for _, rules := range orderedRulesets(blocks) {
		if !orderedDenied(rules.rules, "fetch", "*", false) {
			return false
		}
	}
	return true
}

type orderedRuleset struct {
	where string
	rules []orderedRule
}

// orderedRulesets returns the rule list each agent runs with: the top-level
// rules, then that agent's own, which come later and so win.
func orderedRulesets(blocks []parser.OpenCodePermissionBlock) []orderedRuleset {
	var base []orderedRule
	for _, b := range blocks {
		if b.Top() {
			base = append(base, b.Rules...)
		}
	}
	out := []orderedRuleset{{where: "", rules: base}}
	for _, b := range blocks {
		if !b.Top() {
			out = append(out, orderedRuleset{where: b.Where, rules: append(base[:len(base):len(base)], b.Rules...)})
		}
	}
	return out
}

// checkOrderedPolicy checks the neutral policy against an agent that resolves
// rules by the last match (#1515). Each agent's list is checked, because an
// agent block can reopen what the top level denies.
func checkOrderedPolicy(t *Target, sp policySpelling) []finding.Finding {
	var findings []finding.Finding
	add := func(msg string) {
		findings = append(findings, finding.Finding{RuleID: "CFG025", Severity: finding.Error, File: t.PolicyFile, Message: msg})
	}
	urls := t.PolicyAgent == "kilo-code"
	in := func(where string) string {
		if where == "" {
			return ""
		}
		return " in " + where
	}
	for _, c := range policyCategories {
		if c.key == sp.unenforced {
			continue
		}
		for _, set := range orderedRulesets(t.PolicyBlocks) {
			for _, v := range c.entries(t.PolicyDeny) {
				if !orderedDenied(set.rules, c.key, v, urls) {
					add("policy deny." + c.key + " \"" + v + "\": no rule denies it as the last match" + in(set.where) + ", so " + sp.name +
						" does not block it; add " + orderedSpell(c.key, v, urls) + " after the rules it has to override")
				}
			}
			for _, v := range c.entries(t.PolicyForbid) {
				if r, ok := orderedGrant(set.rules, c.key, v, urls); ok {
					add("policy forbid-allow." + c.key + " \"" + v + "\": \"" + r.Spelled() + "\" rule \"" + r.Resource + "\" allows it" + in(set.where) + ", so " + sp.name + " runs it without asking")
				}
			}
		}
	}
	return findings
}
