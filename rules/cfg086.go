// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

type cfg086 struct{}

var CFG086 = &cfg086{}

func init() { All = append(All, CFG086) }

func (r *cfg086) ID() string { return "CFG086" }

// startingASession is the "when" phrasing for an agent whose only event of this
// kind is its session start.
const startingASession = "starting a session"

// cursorZeroClickEvents fire without the user asking the agent to do anything.
// workspaceOpen fires "when Cursor opens a workspace and on every workspace
// folder change". sessionStart is not tied to opening the project: Cursor 3.29.9
// fires it when a composer is created (createComposerImpl), and the 2026.11.05
// CLI at the start of a run that resumes nothing, both before any prompt (#1186).
//
// Keys are the normalized event name (see normalizeHookEvent): matched with case,
// separators, and spelling collapsed, because Copilot accepts camelCase and
// PascalCase for every event and Grok additionally accepts snake_case
// (session_start). A rule keyed to one spelling would miss files written another.
var cursorZeroClickEvents = map[string]string{
	"workspaceopen": "opening the workspace, and again on every workspace folder change",
	"sessionstart":  "starting a conversation (a new chat in the IDE, or a new CLI run)",
}

// sessionZeroClickEvents are the same for Copilot and Grok, which have no
// workspace-open event.
var sessionZeroClickEvents = map[string]string{"sessionstart": startingASession}

// agentHookZeroClickEvents returns the events of the agent named by kind.
func agentHookZeroClickEvents(kind string) map[string]string {
	if kind == "Cursor" {
		return cursorZeroClickEvents
	}
	return sessionZeroClickEvents
}

// normalizeHookEvent lower-cases an event name and strips the separators that
// vary between agents' spellings, so SessionStart / sessionStart / session_start
// all map to the same key.
func normalizeHookEvent(e string) string {
	e = strings.ToLower(strings.TrimSpace(e))
	e = strings.ReplaceAll(e, "_", "")
	e = strings.ReplaceAll(e, "-", "")
	return e
}

// Check flags a committed hook that runs on an event requiring no user action, in
// Cursor's .cursor/hooks.json, Copilot's .github/hooks/*.json, or xAI Grok's
// .grok/hooks/*.json. The content of the command is judged separately by the
// command-content rules; this rule is about the trigger, which is a finding even
// when the command looks innocuous — the same reasoning as CFG047 for
// .vscode/tasks.json runOn: folderOpen, and CFG067 for committed Claude hooks.
func (r *cfg086) Check(t *Target) []finding.Finding {
	var findings []finding.Finding

	// Cursor / Copilot (AgentHooks: a flat event → handlers map). Copilot's
	// disableAllHooks turns the whole file off.
	if ah := t.AgentHooks; ah != nil && !ah.DisableAllHooks && len(ah.Hooks) > 0 {
		events := agentHookZeroClickEvents(t.AgentHooksKind)
		for _, event := range sortedKeys2(ah.Hooks) {
			when, zeroClick := events[normalizeHookEvent(event)]
			if !zeroClick {
				continue
			}
			for _, h := range ah.Hooks[event] {
				if h.ShellCommand() == "" {
					continue // a prompt or http hook runs no command
				}
				findings = append(findings, zeroClickFinding(t, t.AgentHooksKind, event, when, t.AgentHooksFile))
				break // one finding per event; the command content is judged separately
			}
		}
	}

	// Continue (.continue/settings.json: event → matcher groups → handlers).
	// SessionStart is the zero-click event; Continue matches event names by exact
	// lookup against its declared list, so the literal spelling is what fires.
	//
	// This is the strongest case in the rule: Continue's hook path has no trust
	// gate at all — HookService loads the config and fires the event, with
	// disableAllHooks as the only switch — so a committed SessionStart command
	// hook runs on whoever opens the repo, unprompted. (Codex's hooks look
	// identical in shape but are content-hash trust-gated, which is why they are
	// deliberately absent from this rule.)
	if ch := t.ContinueHooks; ch != nil && !ch.DisableAllHooks && len(ch.Hooks) > 0 {
		if groups, ok := ch.Hooks[continueZeroClickEvent]; ok && grokEventHasCommand(groups, nil) {
			findings = append(findings, zeroClickFinding(t, "Continue", continueZeroClickEvent, startingASession, t.ContinueHooksFile))
		}
	}

	// Grok (.grok/hooks/*.json: event → matcher groups → command handlers). Grok
	// has SessionStart as its zero-click event and no disableAllHooks switch.
	if gh := t.GrokHooks; gh != nil && len(gh.Hooks) > 0 {
		for _, event := range sortedKeys2(gh.Hooks) {
			when, zeroClick := sessionZeroClickEvents[normalizeHookEvent(event)]
			if !zeroClick {
				continue
			}
			if grokEventHasCommand(gh.Hooks[event], nil) {
				findings = append(findings, zeroClickFinding(t, "Grok", event, when, t.GrokHooksFile))
			}
		}
	}

	// Gemini (.gemini/settings.json: event → matcher groups → command handlers).
	// SessionStart is Gemini's only zero-click event (BeforeAgent needs a submitted
	// prompt), and Gemini matches event names as EXACT PascalCase with no
	// normalization — so this checks the literal spelling, not a collapsed key, to
	// avoid flagging a misspelled hook Gemini would silently never run.
	// hooksConfig.enabled: false / disabled turn hooks off (honored in commandSites
	// and here).
	if g := t.Gemini; g != nil && !g.HooksDisabled() && len(g.Hooks) > 0 {
		if groups, ok := g.Hooks[geminiZeroClickEvent]; ok && grokEventHasCommand(groups, g.DisabledHookNames()) {
			if t.GeminiExtensionPublished {
				// A published extension's hook runs for whoever installs it, and
				// Gemini's install consent says the extension has hooks
				// (extensionConsentString, consent.ts), so it is not zero-click
				// for someone who opens this repository (#1556).
				findings = append(findings, finding.Finding{RuleID: "CFG086", Severity: finding.Info, Scope: t.Scope, File: t.GeminiFile,
					Message: "Gemini extension hooks." + geminiZeroClickEvent + " runs a shell command at the start of every session for whoever installs this extension; Gemini's install consent says the extension has hooks, but not which command they run. The command-content rules judge the command"})
			} else {
				findings = append(findings, zeroClickFinding(t, "Gemini", geminiZeroClickEvent, startingASession, t.GeminiFile))
			}
		}
	}

	// qwen (.qwen/settings.json hooks: event → matcher groups → command handlers).
	// qwen matches event names as exact PascalCase (no normalization), its kill
	// switch is top-level disableAllHooks, and it has TWO zero-click events:
	// SessionStart (startup/resume) and InstructionsLoaded (fires while QWEN.md and
	// the context files load at session init, before any user action). Since
	// Qwen Code 0.27.0 project hooks load only after an approval bound to a hash
	// of the hooks (~/.qwen/hookApprovals.json) or in an explicitly trusted
	// folder, and a headless run leaves them unloaded; measured on 0.27.0
	// (#1631). Approved once, the hook runs on every session, so it is warn, not
	// the zero-click error. Older Qwen versions ran it with no prompt.
	if q := t.Qwen; q != nil && !q.HooksDisabled() {
		hooks := q.HookGroups()
		for _, event := range sortedKeys2(hooks) {
			when, zeroClick := qwenZeroClickEvents[event]
			if !zeroClick {
				continue
			}
			if grokEventHasCommand(hooks[event], nil) {
				findings = append(findings, finding.Finding{RuleID: "CFG086", Severity: finding.Warn, Scope: t.Scope, File: t.QwenFile,
					Message: "qwen hooks." + event + " runs a shell command on " + when + "; Qwen Code 0.27.0 and later ask each user to approve the project's hooks once (older versions run them with no prompt), and after that it runs on every session. Move it to a hook that runs on an explicit action, or to machine-local configuration" + userScopeNote(t)})
			}
		}
	}
	// Devin CLI (.devin/config.json hooks and the standalone .devin/hooks.v1.json:
	// event → matcher groups → command handlers, Claude Code's shape). Devin's
	// hooks reference: "SessionStart fires before any user interaction", and it
	// documents no trust step for project hooks (#613).
	if d := t.Devin; d != nil && len(d.Hooks) > 0 {
		if groups, ok := d.Hooks[devinZeroClickEvent]; ok && grokEventHasCommand(groups, nil) {
			findings = append(findings, zeroClickFinding(t, "Devin", devinZeroClickEvent, startingASession, t.DevinFile))
		}
	}
	return findings
}

// devinZeroClickEvent is Devin CLI's hook event that fires before the user does
// anything. Devin documents the events in Claude Code's exact PascalCase.
const devinZeroClickEvent = "SessionStart"

// continueZeroClickEvent is the Continue hook event that fires before the user
// asks the agent for anything. Continue resolves events by exact name against its
// declared list, so the literal spelling is used rather than a normalized key.
const continueZeroClickEvent = "SessionStart"

// geminiZeroClickEvent is the single Gemini hook event that fires before the user
// asks the agent for anything (on startup and resume). Gemini matches event names
// as exact PascalCase, so the literal spelling is used.
const geminiZeroClickEvent = "SessionStart"

// qwenZeroClickEvents are qwen's exact-PascalCase hook events that fire before the
// user does anything, mapped to the "when" phrasing for the finding message.
var qwenZeroClickEvents = map[string]string{
	"SessionStart":       startingASession,
	"InstructionsLoaded": "loading its instruction files (QWEN.md and context) at session start",
}

// zeroClickFinding builds the shared CFG086 finding for a zero-click hook.
func zeroClickFinding(t *Target, kind, event, when, file string) finding.Finding {
	return finding.Finding{
		RuleID:   "CFG086",
		Severity: finding.Error,
		Scope:    t.Scope,
		File:     file,
		Message: kind + " hooks." + event + " runs a shell command on " + when +
			" — committed to a repository, this executes for every teammate, before they have asked the agent to do anything. Move it to a hook that runs on an explicit action, or to machine-local configuration" + userScopeNote(t),
	}
}

// grokEventHasCommand reports whether any handler in the matcher groups runs a
// shell command (type "command"); an http handler carries a url and no command.
// disabled names handlers switched off by name (Gemini's hooksConfig.disabled),
// which are skipped; pass nil when the format has no such list (Grok).
func grokEventHasCommand(groups []parser.HookGroup, disabled map[string]bool) bool {
	for _, g := range groups {
		for _, h := range g.Hooks {
			if h.Command != "" && !disabled[h.Name] {
				return true
			}
		}
	}
	return false
}

// sortedKeys2 returns the map keys in stable order for deterministic findings.
func sortedKeys2[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
