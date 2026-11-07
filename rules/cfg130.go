// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"sort"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg130 struct{}

var CFG130 = &cfg130{}

func init() { All = append(All, CFG130) }

func (r *cfg130) ID() string { return "CFG130" }

// Check reports the shell commands a goose project file holds, whatever they
// run: the command-content rules add their own findings for what they recognize,
// and a plain command matches none of them (#1414).
func (r *cfg130) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var out []finding.Finding
	for _, c := range t.GooseRecipeCommands {
		out = append(out, finding.Finding{RuleID: "CFG130", Severity: finding.Warn, File: t.GooseRecipeFile, Line: c.Line,
			Message: "goose recipe sets " + c.Key + ", a shell command goose runs when someone runs this recipe. The goose CLI shows no trust prompt for it, and goose Desktop asks on first use, so read the command before running the recipe"})
	}
	if h := t.GooseHooks; h != nil {
		events := make([]string, 0, len(h.Hooks))
		for e := range h.Hooks {
			events = append(events, e)
		}
		sort.Strings(events)
		for _, event := range events {
			for _, group := range h.Hooks[event] {
				for _, c := range group.Hooks {
					if gooseRunsHook(c.Type, c.Command) {
						out = append(out, finding.Finding{RuleID: "CFG130", Severity: finding.Warn, File: t.GooseHooksFile,
							Message: "goose project plugin sets hooks." + event + ", a shell command goose runs through sh -c in a session started from this project, with no confirmation documented. Read it, or list the plugin under disabledPlugins"})
					}
				}
			}
		}
	}
	return out
}

// gooseRunsHook mirrors crates/goose/src/hooks/mod.rs: only a "command" action
// with a command runs.
func gooseRunsHook(kind, command string) bool {
	return kind == "command" && command != ""
}
