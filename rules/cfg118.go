// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"slices"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg118 struct{}

// CFG118 reports, once per agent, an agent in the policy's scope that has no
// committed permission file, so no policy.deny entry can be written for it
// (#1081).
var CFG118 = &cfg118{}

func init() { All = append(All, CFG118) }

func (r *cfg118) ID() string { return "CFG118" }

// Check is info, not a violation: nothing in the repository is wrong, but the
// policy reads as covering an agent it cannot reach, and a reviewer should
// know what it takes to enforce the rule there.
func (r *cfg118) Check(t *Target) []finding.Finding {
	if t == nil || len(t.PolicyUnenforceable) == 0 {
		return nil
	}
	var findings []finding.Finding
	for _, a := range t.PolicyUnenforceable {
		var categories []string
		for _, c := range policyCategories {
			if len(c.entries(t.PolicyDeny)) > 0 && (len(a.Categories) == 0 || slices.Contains(a.Categories, c.key)) {
				categories = append(categories, "deny."+c.key)
			}
		}
		if len(categories) == 0 {
			continue
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG118",
			Severity: finding.Info,
			File:     a.Path,
			Message:  "policy " + strings.Join(categories, ", ") + " cannot be enforced for " + a.Name + " from a permission file in the repository: " + a.Name + " " + a.Reason,
		})
	}
	return findings
}
