// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strconv"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg117 struct{}

var CFG117 = &cfg117{}

func init() { All = append(All, CFG117) }

func (r *cfg117) ID() string { return "CFG117" }

// Check reports a key a Claude Code settings file defines more than once
// (#1042). Claude Code keeps the last occurrence and ignores the others:
// measured on 2.1.312, a SessionStart hook under the second of two "hooks" keys
// runs and one under the first does not; on 2.1.314 the same holds for two
// "SessionStart" keys inside one "hooks" object. cfgaudit decodes the file the
// same way, so the other rules already judge the values in force. What this
// rule adds is the hint for the reader: the occurrence a reviewer reads first
// is not the configuration the agent uses, and the one it does use can be the
// risky one. The finding sits on each ignored occurrence and names the line of
// the one that wins. Comment keys ("//") are left out: files repeat them on
// purpose.
func (r *cfg117) Check(t *Target) []finding.Finding {
	if t == nil || t.Settings == nil || len(t.Settings.DuplicateKeys) == 0 {
		return nil
	}
	var out []finding.Finding
	for _, d := range t.Settings.DuplicateKeys {
		out = append(out, finding.Finding{
			RuleID:   "CFG117",
			Severity: finding.Warn,
			Scope:    t.Scope,
			File:     t.SettingsFile,
			Line:     d.Line,
			Col:      d.Col,
			Message: d.Path + " is defined again at line " + strconv.Itoa(d.WinLine) +
				"; Claude Code uses that last occurrence and ignores this one, so what a reviewer reads here is not in force." +
				" Remove the duplicate and keep one " + d.Path,
		})
	}
	return out
}
