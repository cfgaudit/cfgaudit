// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"slices"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg025 struct{}

var CFG025 = &cfg025{}

func init() { All = append(All, CFG025) }

func (r *cfg025) ID() string { return "CFG025" }

// Check enforces the organisation's custom permission policy from .cfgaudit.yml:
//
//   - require-deny: each listed command must be covered by a permissions.deny
//     entry; otherwise it is not actually blocked (deny > allow in Claude Code).
//   - forbid-allow: no permissions.allow entry may grant any of the listed
//     commands.
//
// Inert unless a policy is attached (project-scope target only). Matching is
// containment/overlap-aware so broader patterns subsume narrower ones
// (e.g. Bash(git:*) covers Bash(git commit:*)).
//
// The agent-neutral policy (policy.deny and the mapping form of forbid-allow,
// #1081) is checked against the permission file of each agent it applies to,
// and a missing deny names the entry to add in that agent's syntax.
func (r *cfg025) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	findings := checkNeutralPolicy(t)
	if len(t.PolicyRequireDeny) == 0 && len(t.PolicyForbidAllow) == 0 {
		return findings
	}

	var allow, deny []string
	if t.Settings != nil && t.Settings.Permissions != nil {
		allow = t.Settings.Permissions.Allow
		deny = t.effectiveDeny()
	}

	for _, want := range t.PolicyRequireDeny {
		target, ok := parsePerm(want)
		if !ok {
			continue
		}
		if !anyCovers(deny, target) {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG025",
				Severity: finding.Error,
				File:     t.SettingsFile,
				Message:  "policy: \"" + want + "\" must be blocked by permissions.deny, but no deny entry covers it — it is not actually denied (a broader allow or the default would let it run)" + userScopeNote(t),
			})
		}
	}

	for _, forbidden := range t.PolicyForbidAllow {
		target, ok := parsePerm(forbidden)
		if !ok {
			continue
		}
		if entry, hit := firstOverlap(allow, target); hit {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG025",
				Severity: finding.Error,
				File:     t.SettingsFile,
				Message:  "policy: \"" + forbidden + "\" must not be allowed, but permissions.allow grants it via \"" + entry + "\"" + userScopeNote(t),
			})
		}
	}

	return findings
}

// checkNeutralPolicy checks the agent-neutral policy against the permission
// file of the agent t carries.
func checkNeutralPolicy(t *Target) []finding.Finding {
	sp, ok := policySpellings[t.PolicyAgent]
	if !ok {
		return nil
	}
	var file, note string
	var allow, deny []string
	switch t.PolicyAgent {
	case "claude-code":
		file, note = t.SettingsFile, discardedNote(t)
		deny = t.effectiveDeny()
		if t.Settings != nil && t.Settings.Permissions != nil && !t.discarded() {
			allow = t.Settings.Permissions.Allow
		}
	case "devin":
		file = t.DevinFile
		if t.Devin != nil && t.Devin.Permissions != nil {
			allow, deny = t.Devin.Permissions.Allow, t.Devin.Permissions.Deny
		}
	}

	var findings []finding.Finding
	add := func(msg string) {
		findings = append(findings, finding.Finding{RuleID: "CFG025", Severity: finding.Error, File: file, Message: msg})
	}
	for _, c := range policyCategories {
		for _, v := range c.entries(t.PolicyDeny) {
			if !slices.ContainsFunc(deny, func(e string) bool { return sp.covers(c.key, e, v) }) {
				add("policy deny." + c.key + " \"" + v + "\": no permissions.deny entry covers it, so " + sp.name +
					" does not block it; add \"" + sp.spell(c.key, v) + "\"" + note)
			}
		}
		for _, v := range c.entries(t.PolicyForbid) {
			if i := slices.IndexFunc(allow, func(e string) bool { return sp.overlaps(c.key, e, v) }); i >= 0 {
				add("policy forbid-allow." + c.key + " \"" + v + "\": permissions.allow grants it via \"" + allow[i] +
					"\", so " + sp.name + " runs it without asking")
			}
		}
	}
	return findings
}

func anyCovers(entries []string, target permPattern) bool {
	for _, e := range entries {
		if p, ok := parsePerm(e); ok && covers(p, target) {
			return true
		}
	}
	return false
}

func firstOverlap(entries []string, target permPattern) (string, bool) {
	for _, e := range entries {
		if p, ok := parsePerm(e); ok && overlap(p, target) {
			return e, true
		}
	}
	return "", false
}

// permPattern is a parsed Claude Code permission entry, e.g. Bash(git commit:*).
type permPattern struct {
	tool     string // e.g. "Bash"
	prefix   string // command prefix, space-separated tokens; "" matches everything
	wildcard bool   // true when the entry permits trailing arguments (`:*`, ` *`, `*`)
}

// parsePerm parses "Tool(body)" into a permPattern.
func parsePerm(s string) (permPattern, bool) {
	s = strings.TrimSpace(s)
	open := strings.IndexByte(s, '(')
	if open <= 0 || !strings.HasSuffix(s, ")") {
		return permPattern{}, false
	}
	p := permPattern{tool: s[:open]}
	body := strings.TrimSpace(s[open+1 : len(s)-1])
	switch {
	case body == "*":
		p.wildcard = true
	case strings.HasSuffix(body, ":*"):
		p.wildcard = true
		p.prefix = strings.TrimSpace(strings.TrimSuffix(body, ":*"))
	case strings.HasSuffix(body, "*"):
		p.wildcard = true
		p.prefix = strings.TrimSpace(strings.TrimSuffix(body, "*"))
	default:
		p.prefix = body
	}
	return p, true
}

// hasCmdPrefix reports whether command cmd begins with prefix at a token
// boundary. An empty prefix matches everything.
func hasCmdPrefix(cmd, prefix string) bool {
	if prefix == "" {
		return true
	}
	return cmd == prefix || strings.HasPrefix(cmd, prefix+" ")
}

// covers reports whether permission e grants every command that t matches
// (e ⊇ t) — used for require-deny.
func covers(e, t permPattern) bool {
	if e.tool != t.tool {
		return false
	}
	if !e.wildcard {
		return !t.wildcard && e.prefix == t.prefix
	}
	return hasCmdPrefix(t.prefix, e.prefix)
}

// overlap reports whether permission e grants at least one command that t also
// matches (e ∩ t ≠ ∅) — used for forbid-allow.
func overlap(e, t permPattern) bool {
	if e.tool != t.tool {
		return false
	}
	switch {
	case e.wildcard && t.wildcard:
		return hasCmdPrefix(e.prefix, t.prefix) || hasCmdPrefix(t.prefix, e.prefix)
	case e.wildcard:
		return hasCmdPrefix(t.prefix, e.prefix)
	case t.wildcard:
		return hasCmdPrefix(e.prefix, t.prefix)
	default:
		return e.prefix == t.prefix
	}
}
