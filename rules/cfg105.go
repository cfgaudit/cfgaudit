package rules

import (
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

type cfg105 struct{}

// CFG105 reports a committed OpenCode permission block that resolves one of the
// agent's two remaining guard rails to "allow".
var CFG105 = &cfg105{}

func init() { All = append(All, CFG105) }

func (r *cfg105) ID() string { return "CFG105" }

// envResources are the read patterns OpenCode's default ruleset puts on "ask".
// From packages/core/src/plugin/agent.ts:
//
//	{ action: "read", resource: "*.env", effect: "ask" },
//	{ action: "read", resource: "*.env.*", effect: "ask" },
//	{ action: "read", resource: "*.env.example", effect: "allow" },
//
// The example file is already allowed by default, so re-allowing it changes
// nothing and is not checked.
var envResources = []string{"*.env", "*.env.*"}

// externalDirectoryProbes are the paths a rule has to cover before the grant is
// worth reporting: everything, the whole home directory, or the filesystem root.
// A scoped grant is documented usage ("this allows access to everything under
// ~/projects/personal/"), so naming a specific directory is not a finding.
// Ordered widest first, and only the widest match is reported.
var externalDirectoryProbes = []struct{ path, label string }{
	{"*", "every path outside the working directory"},
	{"~/anything", "the whole home directory"},
	{"/anything", "the filesystem root"},
}

// Check reports the two mechanisms a committed permission block can switch off.
//
// Nearly every OpenCode permission default is already "allow" — the ruleset
// opens with {action: "*", resource: "*", effect: "allow"} — so the ordinary
// "bash": "allow" or "edit": "allow" restates the default and is never a
// finding. What the defaults still hold back is external_directory (ask) and
// reading a .env file (ask), and config rules are pushed AFTER the defaults, so
// a later matching rule wins by findLast.
//
// doom_loop is documented as defaulting to ask and does not appear in the
// defaults ruleset in the source, so it is deliberately not checked; see the
// rule doc.
func (r *cfg105) Check(t *Target) []finding.Finding {
	if t == nil || t.OpenCode == nil {
		return nil
	}
	var findings []finding.Finding
	for _, block := range t.OpenCode.PermissionBlocks() {
		add := func(msg string) {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG105",
				Severity: finding.Warn,
				Scope:    t.Scope,
				File:     t.OpenCodeFile,
				Message:  block.Where + " " + msg,
			})
		}

		for _, probe := range externalDirectoryProbes {
			rule, ok := lastMatching(block.Rules, "external_directory", probe.path)
			if !ok || rule.Effect != "allow" {
				continue
			}
			add("resolves external_directory to \"allow\" for " + probe.label + " (" + describeRule(rule) + ") — OpenCode asks before a tool touches a path outside the working directory, and this removes that prompt for everyone who opens the repository. Name the directories the project needs instead of a pattern that covers the whole home directory or filesystem")
			break
		}
		for _, res := range envResources {
			rule, ok := lastMatching(block.Rules, "read", res)
			if !ok || rule.Effect != "allow" {
				continue
			}
			add("resolves reading " + res + " to \"allow\" (" + describeRule(rule) + ") — OpenCode's defaults put .env files on \"ask\" even though read is otherwise allowed, and a later rule wins, so this silently removes the prompt in front of the file where secrets usually are." +
				" Keep the default by restoring both patterns, for example {\"*\": \"allow\", \"*.env\": \"ask\", \"*.env.*\": \"ask\"}")
			break
		}
	}
	return findings
}

// lastMatching returns the rule that decides an action/resource pair the way
// OpenCode decides it: the LAST rule whose action and resource both match,
// wildcards included. Reports false when nothing in the block matches, which
// means the default stands.
func lastMatching(rules []parser.OpenCodePermissionRule, action, resource string) (parser.OpenCodePermissionRule, bool) {
	var out parser.OpenCodePermissionRule
	var found bool
	for _, rule := range rules {
		if wildcardCovers(rule.Action, action) && wildcardCovers(rule.Resource, resource) {
			out, found = rule, true
		}
	}
	return out, found
}

// wildcardCovers reports whether a rule's pattern covers a value. "*" covers
// everything; otherwise the pattern's own wildcards are expanded.
func wildcardCovers(pattern, value string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "*" || pattern == value {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return false
	}
	var b strings.Builder
	b.WriteString("^")
	for _, part := range strings.Split(pattern, "*") {
		b.WriteString(regexp.QuoteMeta(part))
		b.WriteString(".*")
	}
	// Drop the trailing ".*" added after the final part, then anchor.
	expr := strings.TrimSuffix(b.String(), ".*") + "$"
	re, err := regexp.Compile(expr)
	if err != nil {
		return false
	}
	return re.MatchString(value)
}

// describeRule renders the rule that decided the outcome, so a reader can find
// the line rather than the mechanism.
func describeRule(rule parser.OpenCodePermissionRule) string {
	if rule.Resource == "*" {
		return "from \"" + rule.Action + "\": \"" + rule.Effect + "\""
	}
	return "from \"" + rule.Action + "\": {\"" + rule.Resource + "\": \"" + rule.Effect + "\"}"
}
