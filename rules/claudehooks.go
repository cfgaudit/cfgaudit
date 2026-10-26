// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"sort"

	"github.com/cfgaudit/cfgaudit/internal/parser"
)

// claudeHookSet is one source of Claude Code hooks: a settings file, a plugin
// hooks.json (which rides a settings-shaped target) or a subagent's frontmatter.
type claudeHookSet struct {
	label string // prefixed to "hooks.<event>" in a finding
	file  string
	hooks map[string][]parser.HookGroup
}

func claudeHookSets(t *Target) []claudeHookSet {
	if t == nil {
		return nil
	}
	var sets []claudeHookSet
	if t.Settings != nil && len(t.Settings.Hooks) > 0 {
		sets = append(sets, claudeHookSet{file: t.SettingsFile, hooks: t.Settings.Hooks})
	}
	if len(t.SubagentHooks) > 0 {
		sets = append(sets, claudeHookSet{label: "subagent frontmatter ", file: t.SubagentHooksFile, hooks: t.SubagentHooks})
	}
	return sets
}

// each calls fn for every handler of the set, by event name.
func (s claudeHookSet) each(fn func(loc string, h parser.HookCommand)) {
	events := make([]string, 0, len(s.hooks))
	for e := range s.hooks {
		events = append(events, e)
	}
	sort.Strings(events)
	for _, event := range events {
		for _, group := range s.hooks[event] {
			for _, h := range group.Hooks {
				fn(s.label+"hooks."+event, h)
			}
		}
	}
}
