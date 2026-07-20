package rules

import (
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg086 struct{}

var CFG086 = &cfg086{}

func init() { All = append(All, CFG086) }

func (r *cfg086) ID() string { return "CFG086" }

// zeroClickHookEvents fire without the user asking the agent to do anything —
// opening the folder or starting a session is enough. Cursor's workspaceOpen
// fires "once when Cursor opens a workspace and again on every workspace folder
// change"; the session events fire as soon as a session begins.
//
// Matched case-insensitively because Copilot accepts both a camelCase and a
// PascalCase spelling of every event (sessionStart / SessionStart), and a rule
// keyed to one would miss files written with the other.
var zeroClickHookEvents = map[string]string{
	"workspaceopen": "opening the workspace — and again on every workspace folder change",
	"sessionstart":  "starting a session",
}

// Check flags a committed Cursor or Copilot hook that runs on an event requiring
// no user action. The content of the command is judged separately by the
// command-content rules; this rule is about the trigger, which is a finding even
// when the command looks innocuous — the same reasoning as CFG047 for
// .vscode/tasks.json runOn: folderOpen, and CFG067 for committed Claude hooks.
func (r *cfg086) Check(t *Target) []finding.Finding {
	ah := t.AgentHooks
	if ah == nil || ah.DisableAllHooks || len(ah.Hooks) == 0 {
		return nil
	}
	events := make([]string, 0, len(ah.Hooks))
	for e := range ah.Hooks {
		events = append(events, e)
	}
	sort.Strings(events)

	var findings []finding.Finding
	for _, event := range events {
		when, zeroClick := zeroClickHookEvents[strings.ToLower(strings.TrimSpace(event))]
		if !zeroClick {
			continue
		}
		for _, h := range ah.Hooks[event] {
			if h.ShellCommand() == "" {
				continue // a prompt or http hook runs no command
			}
			findings = append(findings, finding.Finding{
				RuleID:   "CFG086",
				Severity: finding.Error,
				Scope:    t.Scope,
				File:     t.AgentHooksFile,
				Message: t.AgentHooksKind + " hooks." + event + " runs a shell command on " + when +
					" — committed to a repository, this executes on every teammate who opens it, before they have asked the agent to do anything. Move it to a hook that runs on an explicit action, or to machine-local configuration" + userScopeNote(t),
			})
			break // one finding per event; the command content is judged separately
		}
	}
	return findings
}
