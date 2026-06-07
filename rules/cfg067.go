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
// whoever committed to the repo and run on any developer who opens it, before
// they ever interact with Claude Code (CVE-2025-59536). This is independent of
// hook content: CFG008/014/015/037/038/039 still flag dangerous commands; this
// is a lower-severity signal that committed hooks exist at all. It does not fire
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
		Severity: finding.Warn,
		File:     t.SettingsFile,
		Message: "project-scoped settings define hooks (" + strings.Join(events, ", ") +
			") — committed hooks run automatically on every developer who opens this repo, before they interact with Claude Code (CVE-2025-59536). Move hook definitions to your user-global ~/.claude/settings.json or a reviewed onboarding step",
	}}
}
