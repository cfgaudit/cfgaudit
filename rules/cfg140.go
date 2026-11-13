// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

type cfg140 struct{}

// CFG140 reports a Codex .codex/rules file whose forbidden or prompt rules
// match case exactly, and one that uses canonical_matching, which Codex
// 0.166.0 and older cannot parse (#1642).
var CFG140 = &cfg140{}

func init() { All = append(All, CFG140) }

func (r *cfg140) ID() string { return "CFG140" }

// cfg140Quoted is how many rules a finding quotes before it counts the rest.
const cfg140Quoted = 3

// cfg140OldCodex says what happens on a Codex without canonical_matching:
// load_exec_policy_with_warning (core/src/exec_policy.rs, rust-v0.166.0) falls
// back to the requirements policy alone when any rules file fails to parse.
const cfg140OldCodex = "Codex 0.166.0 and older cannot parse the keyword, and when one rules file fails to parse they drop every user and project rule, ~/.codex/rules included, and log only a warning"

// Check reports each rules file once: at info for its forbidden and prompt
// rules without canonical_matching=True, and at info when it uses
// canonical_matching at all.
func (r *cfg140) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	for _, f := range t.CodexRuleFiles {
		var exact []parser.CodexRule
		canonicalLine := 0
		for _, rule := range f.Rules {
			if rule.HasCanonical && canonicalLine == 0 {
				canonicalLine = rule.Line
			}
			if (rule.Decision == "forbidden" || rule.Decision == "prompt") && !rule.Canonical {
				exact = append(exact, rule)
			}
		}
		if canonicalLine > 0 {
			findings = append(findings, finding.Finding{
				RuleID: "CFG140", Severity: finding.Info, File: f.File, Line: canonicalLine, Col: 1,
				Message: "uses canonical_matching, added in Codex 0.167.0; " + cfg140OldCodex + ". Make sure everyone who opens the repository runs Codex 0.167.0 or later",
			})
		}
		if len(exact) == 0 {
			continue
		}
		findings = append(findings, finding.Finding{
			RuleID: "CFG140", Severity: finding.Info, File: f.File, Line: exact[0].Line, Col: 1,
			Message: cfg140ExactMessage(exact),
		})
	}
	return findings
}

// cfg140ExactMessage names the rules that match case exactly.
func cfg140ExactMessage(exact []parser.CodexRule) string {
	var quoted []string
	for i, rule := range exact {
		if i == cfg140Quoted {
			break
		}
		quoted = append(quoted, rule.Decision+" \""+codexPatternText(rule)+"\" (line "+strconv.Itoa(rule.Line)+")")
	}
	list := strings.Join(quoted, ", ")
	if more := len(exact) - len(quoted); more > 0 {
		list += " and " + strconv.Itoa(more) + " more"
	}
	n := strconv.Itoa(len(exact)) + " forbidden or prompt rules match"
	if len(exact) == 1 {
		n = "1 forbidden or prompt rule matches"
	}
	first := exact[0].Pattern[0][0]
	return n + " case exactly: " + list + ". On macOS and Windows, whose file systems ignore case, `" + strings.ToUpper(first) + "` starts the same program as `" + first + "` and walks past the rule. Codex 0.167.0 and later compare a rule caseless with canonical_matching=True; add it once everyone who opens the repository runs 0.167.0 or later, since " + cfg140OldCodex
}
