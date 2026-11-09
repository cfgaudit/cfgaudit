// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg067 struct{}

var CFG067 = &cfg067{}

func init() { All = append(All, CFG067) }

func (r *cfg067) ID() string { return "CFG067" }

// Check flags the mere presence of hooks in a project-scoped settings file
// (.claude/settings.json or settings.local.json). Unlike a user's global
// settings — where hooks are self-intentional — project hooks are placed by
// whoever committed to the repo and run for every developer who trusts the
// folder. Measured with 2.1.316 (#1197): a SessionStart hook did not run while
// the trust dialog was open and ran once "Yes, I trust this folder" was chosen.
// Before the fix for CVE-2025-59536 they ran ahead of that dialog. The trust
// prompt covers the whole folder, not the hooks in it. This is independent of
// hook content: CFG008/014/015/037/038/039 still flag dangerous commands, and
// CFG119 flags a hook that starts a script with payload markers, so this is an
// info-level signal that committed hooks exist at all (#1197). It does not fire
// on user-global settings or on plugin hooks.json (unscoped) targets.
func (r *cfg067) Check(t *Target) []finding.Finding {
	if t == nil || t.Settings == nil {
		return nil
	}
	if t.Scope != finding.ScopeProject && t.Scope != finding.ScopeProjectLocal {
		return nil
	}
	var events []string
	for ev, groups := range t.Settings.Hooks {
		if len(groups) > 0 {
			events = append(events, ev)
		}
	}
	if len(events) == 0 {
		return nil
	}
	sort.Strings(events)
	return []finding.Finding{{
		RuleID:   "CFG067",
		Severity: finding.Info,
		File:     t.SettingsFile,
		Key:      "hooks",
		Message: "project-scoped settings define hooks (" + strings.Join(events, ", ") +
			") — committed hooks run for every developer who trusts this folder in Claude Code; the trust prompt covers the whole folder and does not show the hooks. Review what they run, and move personal hooks to your user-global ~/.claude/settings.json",
	}}
}
