// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"encoding/json"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// rooAllowedCommandsKey is Roo Code's list of command prefixes it runs
// without asking (#989): "Add * to allow all commands (use with caution)"
// (auto-approving-actions docs). A prefix matches any command that starts
// with it, so "bash" or "python" allows "bash -c <anything>". The list takes
// effect when the user has turned on auto-approval of allowed commands in Roo
// Code, a global switch the repository cannot set, so it is reported at warn.
const rooAllowedCommandsKey = "roo-cline.allowedCommands"

// checkRooAllowedCommands reports "*" and interpreter prefixes in a committed
// roo-cline.allowedCommands.
func (r *cfg048) checkRooAllowedCommands(t *Target) []finding.Finding {
	raw, ok := t.VSCodeSettings.RawValue(rooAllowedCommandsKey)
	if !ok {
		return nil
	}
	var cmds []string
	if json.Unmarshal(raw, &cmds) != nil {
		return nil
	}
	var broad []string
	for _, c := range cmds {
		c = strings.TrimSpace(c)
		f := strings.Fields(c)
		if c == "*" || (len(f) == 1 && (shellInterpreters[f[0]] || languageInterpreters[f[0]])) {
			broad = append(broad, c)
		}
	}
	if len(broad) == 0 {
		return nil
	}
	return []finding.Finding{{
		RuleID:   "CFG048",
		Severity: finding.Warn,
		Scope:    t.Scope,
		File:     t.VSCodeSettingsFile,
		Key:      rooAllowedCommandsKey,
		Message:  rooAllowedCommandsKey + " approves " + quoteList(broad) + " — Roo Code matches the list by prefix, so this runs any command (an interpreter prefix runs any script it is given) without a prompt once its auto-approval of allowed commands is on. Committed to a repo, the list applies to everyone who opens it with Roo Code. List the specific commands the project needs" + nestedNote(t, rooAllowedCommandsKey),
	}}
}
