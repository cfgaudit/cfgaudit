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

// zeroClickHookEvents fire without the user asking the agent to do anything —
// opening the folder or starting a session is enough. Cursor's workspaceOpen
// fires "once when Cursor opens a workspace and again on every workspace folder
// change"; the session events fire as soon as a session begins.
//
// Keys are the normalized event name (see normalizeHookEvent): matched with case,
// separators, and spelling collapsed, because Copilot accepts camelCase and
// PascalCase for every event and Grok additionally accepts snake_case
// (session_start). A rule keyed to one spelling would miss files written another.
var zeroClickHookEvents = map[string]string{
	"workspaceopen": "opening the workspace — and again on every workspace folder change",
	"sessionstart":  "starting a session",
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
		for _, event := range sortedKeys2(ah.Hooks) {
			when, zeroClick := zeroClickHookEvents[normalizeHookEvent(event)]
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

	// Grok (.grok/hooks/*.json: event → matcher groups → command handlers). Grok
	// has SessionStart as its zero-click event and no disableAllHooks switch.
	if gh := t.GrokHooks; gh != nil && len(gh.Hooks) > 0 {
		for _, event := range sortedKeys2(gh.Hooks) {
			when, zeroClick := zeroClickHookEvents[normalizeHookEvent(event)]
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
			findings = append(findings, zeroClickFinding(t, "Gemini", geminiZeroClickEvent, zeroClickHookEvents["sessionstart"], t.GeminiFile))
		}
	}
	return findings
}

// geminiZeroClickEvent is the single Gemini hook event that fires before the user
// asks the agent for anything (on startup and resume). Gemini matches event names
// as exact PascalCase, so the literal spelling is used.
const geminiZeroClickEvent = "SessionStart"

// zeroClickFinding builds the shared CFG086 finding for a zero-click hook.
func zeroClickFinding(t *Target, kind, event, when, file string) finding.Finding {
	return finding.Finding{
		RuleID:   "CFG086",
		Severity: finding.Error,
		Scope:    t.Scope,
		File:     file,
		Message: kind + " hooks." + event + " runs a shell command on " + when +
			" — committed to a repository, this executes on every teammate who opens it, before they have asked the agent to do anything. Move it to a hook that runs on an explicit action, or to machine-local configuration" + userScopeNote(t),
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
