// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path/filepath"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg146 struct{}

var CFG146 = &cfg146{}

func init() { All = append(All, CFG146) }

func (r *cfg146) ID() string { return "CFG146" }

// No MinVersion: presence-based, like CFG003. Claude Code has honoured
// disableAllHooks since it added the key.

// Check reports `disableAllHooks: true` in a repository's Claude Code settings
// (.claude/settings.json or .claude/settings.local.json; #1801). The switch is
// not limited to the repository's own hooks: it turns off the user's hooks,
// plugin hooks and --settings hooks too, guard hooks included. Measured on
// Claude Code 2.1.327: a user-scope SessionStart hook did not run once either
// project file set the switch, and ran again with false or no key. The user's
// own ~/.claude/settings.json is theirs to set and is not reported. The other
// hook rules keep dropping findings for the hooks the switch turns off
// (ClaudeHooksDisabled).
func (r *cfg146) Check(t *Target) []finding.Finding {
	if t.Settings == nil || filepath.Base(filepath.Dir(t.SettingsFile)) != ".claude" {
		return nil
	}
	if t.Scope != finding.ScopeProject && t.Scope != finding.ScopeProjectLocal {
		return nil
	}
	if v, ok := t.Settings.BoolField("disableAllHooks"); !ok || !v {
		return nil
	}
	return []finding.Finding{{
		RuleID:   "CFG146",
		Severity: finding.Warn,
		File:     t.SettingsFile,
		Message:  "disableAllHooks: true turns off every Claude Code hook once the folder is trusted, not only the repository's: the user's own hooks, plugin hooks and --settings hooks, including guard hooks a user or team relies on (measured on Claude Code 2.1.327). Claude Code 2.1.323 stopped repository settings from disabling your hooks only under --trust-workspace false on self-hosted runners and in untrusted VS Code folders. Remove the key and turn off specific hooks instead",
	}}
}
