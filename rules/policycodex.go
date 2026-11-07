// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

const codexRulesHint = ".codex/rules/"

// codexForbidden reports whether a rule forbids v. Every matching
// rule counts and the strictest decision wins, so one forbidden rule is enough
// and order does not matter.
func codexForbidden(rules []parser.CodexRule, v string) bool {
	command := strings.Fields(v)
	for _, r := range rules {
		if r.Decision == "forbidden" && r.MatchesPrefix(command) {
			return true
		}
	}
	return false
}

// codexCommandGrant returns an allow rule that covers something v names, unless
// a forbidden rule takes v itself.
func codexCommandGrant(rules []parser.CodexRule, v string) (parser.CodexRule, bool) {
	if codexForbidden(rules, v) {
		return parser.CodexRule{}, false
	}
	command := strings.Fields(v)
	for _, r := range rules {
		if r.Decision == "allow" && (r.MatchesPrefix(command) || r.Under(command)) {
			return r, true
		}
	}
	return parser.CodexRule{}, false
}

func codexPatternText(r parser.CodexRule) string {
	var parts []string
	for _, alts := range r.Pattern {
		parts = append(parts, strings.Join(alts, "|"))
	}
	return strings.Join(parts, " ")
}

func codexRuleSpell(v string) string {
	var toks []string
	for _, t := range strings.Fields(v) {
		toks = append(toks, strconv.Quote(t))
	}
	return "prefix_rule(pattern=[" + strings.Join(toks, ", ") + `], decision="forbidden")`
}

// codexBlocks reports whether a filesystem decision takes the access away:
// deny, with none as its legacy spelling, blocks both, and read blocks writes.
func codexBlocks(decision, category string) bool {
	d := strings.ToLower(strings.TrimSpace(decision))
	return d == "deny" || d == "none" || (category == "write" && d == "read")
}

// codexPathDenied looks through the selected profile and the ones it extends.
// A home path is a key of the filesystem table, as a directory or a glob, and a
// repository path a key of a workspace scope.
func codexPathDenied(profiles []parser.NamedCodexProfile, category, v string) bool {
	for _, np := range profiles {
		for key, val := range np.Profile.Filesystem {
			k := strings.TrimSpace(key)
			switch d := val.(type) {
			case string:
				if !codexBlocks(d, category) {
					continue
				}
				if k == ":root" {
					return true
				}
				if strings.HasPrefix(v, "~/") {
					if k == v || strings.HasPrefix(v, strings.TrimSuffix(k, "/**")+"/") {
						return true
					}
				} else if k == ":workspace_roots" || k == ":project_roots" {
					return true
				}
			case map[string]any:
				if k != ":workspace_roots" && k != ":project_roots" && k != ":root" {
					continue
				}
				for glob, decision := range d {
					s, ok := decision.(string)
					if ok && codexBlocks(s, category) && globCovers(strings.TrimSpace(glob), v) {
						return true
					}
				}
			}
		}
	}
	return false
}

// codexProfileName is the selected profile, or the name a new one would have.
func codexProfileName(profiles []parser.NamedCodexProfile) string {
	if len(profiles) > 0 {
		return profiles[0].Name
	}
	return "policy"
}

// codexPathSpell is the entry to add. Nothing filesystem-related applies
// without a selected profile, so the suggestion says so.
func codexPathSpell(profiles []parser.NamedCodexProfile, category, v string) string {
	decision := "deny"
	if category == "write" {
		decision = "read"
	}
	name := codexProfileName(profiles)
	var out string
	if strings.HasPrefix(v, "~/") {
		out = strconv.Quote(strings.TrimSuffix(v, "/**")) + ` = "deny" under [permissions.` + name + ".filesystem]"
	} else {
		out = strconv.Quote(v) + " = " + strconv.Quote(decision) + ` under [permissions.` + name + `.filesystem.":workspace_roots"]`
	}
	return out + codexSelectNote(profiles)
}

func codexSelectNote(profiles []parser.NamedCodexProfile) string {
	if len(profiles) > 0 {
		return ""
	}
	return `, with default_permissions = "policy"`
}

// codexFetchDenied checks the selected profile's network block. An explicit
// enabled = false leaves nothing to fetch with; a domain needs its own deny.
func codexFetchDenied(profiles []parser.NamedCodexProfile, v string) bool {
	for _, np := range profiles {
		n := np.Profile.Network
		if n == nil {
			continue
		}
		if n.Enabled != nil && !*n.Enabled {
			return true
		}
		for pattern, decision := range n.Domains {
			p := strings.Replace(strings.TrimSpace(pattern), "**.", "*.", 1)
			if strings.EqualFold(strings.TrimSpace(decision), "deny") && domainCovers(p, v) {
				return true
			}
		}
	}
	return false
}

// codexToolMatch reports whether a tool name is one the entry names.
func codexToolMatch(name, tool string) bool {
	if prefix, ok := strings.CutSuffix(tool, "*"); ok {
		return strings.HasPrefix(name, prefix)
	}
	return name == tool
}

// codexMCPDenied applies enabled_tools and then disabled_tools. A server the
// file does not configure has nothing to deny here: Codex has no rule for a
// server by name, and a table for it needs a transport the policy does not know.
func codexMCPDenied(servers map[string]parser.CodexMCP, v string) bool {
	server, tool, _ := strings.Cut(v, ":")
	s, ok := servers[server]
	if !ok || (s.Enabled != nil && !*s.Enabled) {
		return true
	}
	if s.EnabledTools != nil {
		for _, name := range s.EnabledTools {
			if codexToolMatch(name, tool) {
				return false
			}
		}
		return true
	}
	for _, name := range s.DisabledTools {
		if name == tool {
			return true
		}
	}
	return false
}

// codexMCPGrant reports a server or tool approval that covers v.
func codexMCPGrant(servers map[string]parser.CodexMCP, v string) (string, bool) {
	server, tool, _ := strings.Cut(v, ":")
	s, ok := servers[server]
	if !ok {
		return "", false
	}
	if strings.EqualFold(s.DefaultToolsApprovalMode, "approve") {
		return "default_tools_approval_mode = \"approve\"", true
	}
	for name, t := range s.Tools {
		if strings.EqualFold(t.ApprovalMode, "approve") && codexToolMatch(name, tool) {
			return "tools." + name + ".approval_mode = \"approve\"", true
		}
	}
	return "", false
}

func codexMCPSpell(servers map[string]parser.CodexMCP, v string) string {
	server, tool, _ := strings.Cut(v, ":")
	if strings.HasSuffix(tool, "*") {
		return "each matching tool to disabled_tools, or list the allowed tools in enabled_tools, under [mcp_servers." + server + "]"
	}
	return strconv.Quote(tool) + " to disabled_tools under [mcp_servers." + server + "]"
}

// checkCodexPolicy checks the neutral policy against Codex, where each category
// lives somewhere else: commands in .codex/rules, paths and domains in the
// selected permission profile, and MCP tools per server (#1516).
func checkCodexPolicy(t *Target, sp policySpelling) []finding.Finding {
	var findings []finding.Finding
	add := func(file, msg string) {
		findings = append(findings, finding.Finding{RuleID: "CFG025", Severity: finding.Error, File: file, Message: msg})
	}
	rulesFile := t.CodexRulesFile
	var profiles []parser.NamedCodexProfile
	var servers map[string]parser.CodexMCP
	if t.Codex != nil {
		profiles, servers = t.Codex.SelectedPermissionProfiles(), t.Codex.MCPServers
	}
	missing := func(file, key, v, fix string) {
		add(file, "policy deny."+key+" \""+v+"\": nothing covers it, so "+sp.name+" does not block it; add "+fix)
	}
	for _, c := range policyCategories {
		for _, v := range c.entries(t.PolicyDeny) {
			switch c.key {
			case "commands":
				if !codexForbidden(t.CodexRules, v) {
					missing(rulesFile, c.key, v, codexRuleSpell(v)+" to a file in "+codexRulesHint)
				}
			case "read", "write":
				if !codexPathDenied(profiles, c.key, v) {
					missing(t.CodexFile, c.key, v, codexPathSpell(profiles, c.key, v))
				}
			case "fetch":
				if !codexFetchDenied(profiles, v) {
					missing(t.CodexFile, c.key, v, strconv.Quote(v)+` = "deny" under [permissions.`+codexProfileName(profiles)+".network.domains]"+codexSelectNote(profiles))
				}
			default:
				if !codexMCPDenied(servers, v) {
					missing(t.CodexFile, c.key, v, codexMCPSpell(servers, v))
				}
			}
		}
		for _, v := range c.entries(t.PolicyForbid) {
			switch c.key {
			case "commands":
				if r, ok := codexCommandGrant(t.CodexRules, v); ok {
					add(rulesFile, "policy forbid-allow.commands \""+v+"\": the allow rule \""+codexPatternText(r)+"\" grants it, so "+sp.name+" runs it without asking")
				}
			case "mcp-tools":
				if grant, ok := codexMCPGrant(servers, v); ok {
					add(t.CodexFile, "policy forbid-allow.mcp-tools \""+v+"\": "+grant+" grants it, so "+sp.name+" runs it without asking")
				}
			}
		}
	}
	return findings
}
