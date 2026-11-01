// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg118 struct{}

// CFG118 reports, once per agent, an agent in the policy's scope that reads its
// permission rules from user-level settings only, so no policy.deny entry can
// be committed for it (#1081).
var CFG118 = &cfg118{}

func init() { All = append(All, CFG118) }

func (r *cfg118) ID() string { return "CFG118" }

// Check is info, not a violation: nothing in the repository is wrong, but the
// policy reads as covering an agent it cannot reach, and a reviewer should
// know that each contributor has to set the rule up in their own settings.
func (r *cfg118) Check(t *Target) []finding.Finding {
	if t == nil || len(t.PolicyUnenforceable) == 0 {
		return nil
	}
	var categories []string
	for _, c := range policyCategories {
		if len(c.entries(t.PolicyDeny)) > 0 {
			categories = append(categories, "deny."+c.key)
		}
	}
	if len(categories) == 0 {
		return nil
	}
	var findings []finding.Finding
	for _, a := range t.PolicyUnenforceable {
		findings = append(findings, finding.Finding{
			RuleID:   "CFG118",
			Severity: finding.Info,
			File:     a.Dir,
			Message: "policy " + strings.Join(categories, ", ") + " cannot be enforced for " + a.Name + " from the repository: " + a.Name +
				" reads its permission rules from user settings only, so each contributor has to add the rules to their own settings",
		})
	}
	return findings
}
