// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/config"
	"github.com/cfgaudit/cfgaudit/internal/parser"
	"github.com/cfgaudit/cfgaudit/internal/scanroot"
)

// rulesyncTools maps Rulesync's tool names to the policy's agents.
var rulesyncTools = map[string][]string{
	"claudecode": {"claude-code"}, "codexcli": {"codex"}, "cursor": {"cursor", "cursor-cli"},
	"opencode": {"opencode"}, "opencodev1": {"opencode"}, "kilo": {"kilo-code"}, "qwencode": {"qwen-code"},
	"roo": {"roo-code"}, "cline": {"cline"}, "zed": {"zed"}, "goose": {"goose"}, "devin": {"devin"}, "pi": {"pi"},
}

// rulesyncSource is a loaded file and where it is.
type rulesyncSource struct {
	path  string
	perms *parser.RulesyncPermissions
}

// loadRulesync reads the Rulesync source: the JSONC file wins over the legacy
// JSON file. It returns nil when neither exists or neither parses, since a
// broken source is Rulesync's to report.
func loadRulesync(dir string) *rulesyncSource {
	for _, name := range []string{"permissions.jsonc", "permissions.json"} {
		path := filepath.Join(dir, ".rulesync", name)
		if _, err := scanroot.Stat(path); err != nil {
			continue
		}
		p, err := parser.ParseRulesyncPermissions(path)
		if err != nil || p == nil {
			return nil
		}
		return &rulesyncSource{path, p}
	}
	return nil
}

// rulesFor returns the rules that apply to an agent: a tool's category replaces
// the shared one. "" gives the shared rules.
func (s *rulesyncSource) rulesFor(agent string) parser.RulesyncRules {
	out := parser.RulesyncRules{}
	for c, m := range s.perms.Shared {
		out[c] = m
	}
	for tool, block := range s.perms.Tools {
		if slices.Contains(rulesyncTools[tool], agent) {
			for c, m := range block {
				out[c] = m
			}
		}
	}
	return out
}

var (
	rulesyncMCPRe    = regexp.MustCompile(`^mcp__([^_].*?)(?:__(.+))?$`)
	rulesyncDomainRe = regexp.MustCompile(`^(?:domain:)?((?:\*\.)?[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)$`)
)

// rulesyncCommand turns a bash pattern into a neutral command: a trailing " *"
// or ":*" goes, and a pattern with any other wildcard has no neutral form.
func rulesyncCommand(p string) (string, bool) {
	v := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSpace(p), " *"), ":*")
	return v, v != "" && !strings.ContainsAny(v, "*?")
}

// rulesyncPath turns a path pattern into a neutral path, as written. Rulesync
// passes ".env" to each tool unchanged and the tools read a bare name
// differently, so it is not widened to every depth here.
func rulesyncPath(p string) (string, bool) {
	p = strings.TrimPrefix(strings.TrimSpace(p), "./")
	if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, "..") || p == "*" || p == "**" {
		return "", false
	}
	return p, true
}

// rulesyncEntries sorts a rule set into neutral entries. ask goes to forbid,
// because an agent file must not turn it into allow, and allow constrains
// nothing. A rule with no neutral form comes back in skipped.
func rulesyncEntries(rs parser.RulesyncRules) (deny, forbid config.PolicyRules, skipped []string) {
	for _, category := range rulesyncKeys(rs) {
		patterns := rs[category]
		for _, pattern := range rulesyncKeys(patterns) {
			action := patterns[pattern]
			if action != "deny" && action != "ask" {
				continue
			}
			note := func() { skipped = append(skipped, category+" "+pattern) }
			switch category {
			case "bash":
				v, ok := rulesyncCommand(pattern)
				switch {
				case !ok:
					note()
				case action == "deny":
					deny.Commands = append(deny.Commands, v)
				default:
					forbid.Commands = append(forbid.Commands, v)
				}
			case "read", "edit", "write":
				v, ok := rulesyncPath(pattern)
				switch {
				case action == "ask":
				case !ok:
					note()
				case category == "read":
					deny.Read = append(deny.Read, v)
				default:
					deny.Write = append(deny.Write, v)
				}
			case "webfetch":
				m := rulesyncDomainRe.FindStringSubmatch(strings.TrimSpace(pattern))
				switch {
				case action == "ask":
				case m == nil:
					note()
				default:
					deny.Fetch = append(deny.Fetch, m[1])
				}
			default:
				m := rulesyncMCPRe.FindStringSubmatch(category)
				if m == nil {
					if action == "deny" {
						note()
					}
					continue
				}
				tool := m[2]
				if tool == "" {
					tool = "*"
				}
				if action == "deny" {
					deny.MCPTools = append(deny.MCPTools, m[1]+":"+tool)
				} else {
					forbid.MCPTools = append(forbid.MCPTools, m[1]+":"+tool)
				}
			}
		}
	}
	return deny, forbid, skipped
}

func rulesyncKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// withRulesync adds the Rulesync rules for an agent to the policy.
func withRulesync(p config.Policy, s *rulesyncSource, agent string) config.Policy {
	if s == nil {
		return p
	}
	deny, forbid, _ := rulesyncEntries(s.rulesFor(agent))
	p.Deny = mergePolicyRules(p.Deny, deny)
	p.ForbidAllow.PolicyRules = mergePolicyRules(p.ForbidAllow.PolicyRules, forbid)
	return p
}

func mergePolicyRules(a, b config.PolicyRules) config.PolicyRules {
	merge := func(x, y []string) []string {
		out := slices.Clone(x)
		for _, v := range y {
			if !slices.Contains(out, v) {
				out = append(out, v)
			}
		}
		return out
	}
	return config.PolicyRules{
		Commands: merge(a.Commands, b.Commands), Read: merge(a.Read, b.Read), Write: merge(a.Write, b.Write),
		Fetch: merge(a.Fetch, b.Fetch), MCPTools: merge(a.MCPTools, b.MCPTools),
	}
}

// rulesyncConflicts lists what .cfgaudit.yml denies and the Rulesync file
// allows, in either direction of a word prefix for commands.
func rulesyncConflicts(p config.Policy, s *rulesyncSource) []string {
	var out []string
	shared := s.rulesFor("")
	allows := func(category string, match func(pattern string) bool) string {
		for _, pattern := range rulesyncKeys(shared[category]) {
			if shared[category][pattern] == "allow" && match(pattern) {
				return pattern
			}
		}
		return ""
	}
	for _, v := range p.Deny.Commands {
		if a := allows("bash", func(pattern string) bool {
			c, ok := rulesyncCommand(pattern)
			return ok && (c == v || strings.HasPrefix(c, v+" "))
		}); a != "" {
			out = append(out, "policy deny.commands \""+v+"\" conflicts with the bash rule \""+a+"\": allow in the Rulesync file")
		}
	}
	for _, c := range []struct {
		key      string
		category string
		entries  []string
	}{{"read", "read", p.Deny.Read}, {"write", "edit", p.Deny.Write}, {"write", "write", p.Deny.Write}} {
		for _, v := range c.entries {
			if a := allows(c.category, func(pattern string) bool {
				path, ok := rulesyncPath(pattern)
				return ok && path == v
			}); a != "" {
				out = append(out, "policy deny."+c.key+" \""+v+"\" conflicts with the "+c.category+" rule \""+a+"\": allow in the Rulesync file")
			}
		}
	}
	return out
}
