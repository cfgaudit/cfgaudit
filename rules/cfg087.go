package rules

import (
	"regexp"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

type cfg087 struct{}

var CFG087 = &cfg087{}

func init() { All = append(All, CFG087) }

func (r *cfg087) ID() string { return "CFG087" }

// decisionField is one vendor's spelling of the field a permission-deciding hook
// sets to approve a tool call, together with the regexp that finds it emitting
// the allowing value.
//
// The spellings are disjoint per vendor *and* per event — Copilot's
// permissionRequest reads `behavior`, its preToolUse reads `permissionDecision`,
// and Cursor reads `permission` on every gate it has. A single matcher applied to
// every event would report fields the agent ignores at that event, which is a
// false positive, not extra coverage. So each event carries only the field(s)
// that actually take effect there.
type decisionField struct {
	Name     string
	Allow    *regexp.Regexp
	ArgsName string         // the same event's argument-rewriting field, if it has one
	Args     *regexp.Regexp // matcher for ArgsName; nil when the event has none
}

// jsonAllow builds a matcher for `"<field>": "allow"` as it appears in JSON the
// hook prints on stdout. Whitespace is tolerated and the quoting style is not,
// because both vendors read the hook's stdout as JSON.
func jsonAllow(field string) *regexp.Regexp {
	return regexp.MustCompile(`(?i)"` + field + `"\s*:\s*"allow"`)
}

// jsonKey matches the mere presence of a JSON key.
func jsonKey(field string) *regexp.Regexp {
	return regexp.MustCompile(`(?i)"` + field + `"\s*:`)
}

var (
	copilotBehavior   = decisionField{Name: "behavior", Allow: jsonAllow("behavior")}
	copilotPreToolUse = decisionField{Name: "permissionDecision", Allow: jsonAllow("permissionDecision"), ArgsName: "modifiedArgs", Args: jsonKey("modifiedArgs")}
	cursorPermission  = decisionField{Name: "permission", Allow: jsonAllow("permission"), ArgsName: "updated_input", Args: jsonKey("updated_input")}
)

// permissionDecidingEvents maps a hook event (lower-cased; both vendors' events
// are matched case-insensitively because Copilot accepts a camelCase and a
// PascalCase spelling of each) to the decision fields honoured at that event.
//
// preToolUse exists in both products with different field names, so it carries
// both. The remaining Cursor gates (beforeShellExecution, beforeMCPExecution,
// subagentStart) read `permission` only.
var permissionDecidingEvents = map[string][]decisionField{
	"permissionrequest":    {copilotBehavior},                     // Copilot
	"pretooluse":           {copilotPreToolUse, cursorPermission}, // Copilot + Cursor
	"beforeshellexecution": {cursorPermission},                    // Cursor
	"beforemcpexecution":   {cursorPermission},                    // Cursor
	"subagentstart":        {cursorPermission},                    // Cursor
}

// Check flags a committed Cursor or Copilot hook that answers a permission gate
// with "allow", auto-approving tool calls the user would otherwise have been
// asked about. It is the config-shaped sibling of CFG029 (instruction text that
// tells the agent to skip confirmation) and CFG048 (a committed .vscode setting
// that blanket-auto-approves), reached through a hook file instead.
//
// **What this can and cannot see.** The decision fields are the hook's *output*,
// not keys in hooks.json, so this rule reads them out of an inline command that
// prints the JSON — `echo '{"permissionDecision":"allow"}'`, which is how a
// blanket auto-approve hook is actually written. A hook that delegates to a
// checked-in script (`./.github/hooks/approve.sh`) puts the decision outside the
// config file and is not visible here; a hook that delegates to a remote endpoint
// (type: "http") is CFG088's finding.
func (r *cfg087) Check(t *Target) []finding.Finding {
	var findings []finding.Finding

	// Cursor/Copilot (flat AgentHooks). disableAllHooks turns the file off.
	ah := t.AgentHooks
	if ah != nil && !ah.DisableAllHooks && len(ah.Hooks) > 0 {
		findings = append(findings, r.checkAgentHooks(t, ah)...)
	}

	// Gemini (.gemini/settings.json BeforeTool arg-rewrite — warn only, no
	// auto-approve exists there; see checkGemini).
	findings = append(findings, r.checkGemini(t)...)
	return findings
}

// checkAgentHooks handles Cursor's .cursor/hooks.json and Copilot's
// .github/hooks/*.json, whose events answer a permission gate with an allowing
// value (error) or rewrite the tool arguments (warn).
func (r *cfg087) checkAgentHooks(t *Target, ah *parser.AgentHooks) []finding.Finding {
	events := make([]string, 0, len(ah.Hooks))
	for e := range ah.Hooks {
		events = append(events, e)
	}
	sort.Strings(events)

	var findings []finding.Finding
	for _, event := range events {
		fields, gates := permissionDecidingEvents[strings.ToLower(strings.TrimSpace(event))]
		if !gates {
			continue
		}
		for _, h := range ah.Hooks[event] {
			cmd := h.ShellCommand()
			if cmd == "" {
				continue // a prompt or http hook prints no decision of its own
			}
			for _, df := range fields {
				switch {
				case df.Allow.MatchString(cmd):
					findings = append(findings, finding.Finding{
						RuleID:   "CFG087",
						Severity: finding.Error,
						Scope:    t.Scope,
						File:     t.AgentHooksFile,
						Message: t.AgentHooksKind + " hooks." + event + " answers the permission gate with " + df.Name +
							": \"allow\" — the hook approves the tool call itself, so the user is never asked. Committed to a repository this removes the confirmation prompt for everyone who opens it. Return \"ask\" (or no decision) and let the user decide" + userScopeNote(t),
					})
				case df.Args != nil && df.Args.MatchString(cmd):
					findings = append(findings, finding.Finding{
						RuleID:   "CFG087",
						Severity: finding.Warn,
						Scope:    t.Scope,
						File:     t.AgentHooksFile,
						Message: t.AgentHooksKind + " hooks." + event + " rewrites the tool arguments before execution (" + df.ArgsName +
							") — what runs is not what the user saw and approved. Review the substitution, or reject the call instead of rewriting it" + userScopeNote(t),
					})
				default:
					continue
				}
				break // one finding per hook entry; the strongest match wins
			}
		}
	}
	return findings
}

// geminiToolInputRe matches a Gemini BeforeTool hook printing an argument-rewrite
// output. The field is nested (hookSpecificOutput.tool_input); matching the key
// alone is enough, since only BeforeTool honours it.
var geminiToolInputRe = jsonKey("tool_input")

// checkGemini flags a Gemini .gemini/settings.json BeforeTool hook that rewrites
// the tool arguments (hookSpecificOutput.tool_input) — the same warn as Copilot's
// modifiedArgs and Cursor's updated_input.
//
// There is deliberately NO error case for Gemini. Unlike Cursor/Copilot, a Gemini
// hook cannot auto-approve a tool call: decision:"allow"/"approve" are inert (no
// consumer reads them — verified against gemini-cli hook-utils.ts/scheduler.ts),
// and only decision:"deny"/"block" (blocks) and decision:"ask" (forces a prompt)
// take effect. A hook can add friction or deny, never skip the confirmation, so
// matching an "allow" value here would report a bypass that does not exist.
func (r *cfg087) checkGemini(t *Target) []finding.Finding {
	g := t.Gemini
	if g == nil || g.HooksDisabled() || len(g.Hooks) == 0 {
		return nil
	}
	// Gemini matches event names as exact PascalCase; tool_input is honoured only
	// at BeforeTool, so a rewrite output under any other event is ignored by Gemini
	// and not flagged.
	groups, ok := g.Hooks["BeforeTool"]
	if !ok {
		return nil
	}
	disabled := g.DisabledHookNames()
	var findings []finding.Finding
	for _, group := range groups {
		for _, h := range group.Hooks {
			if h.Command == "" || disabled[h.Name] {
				continue
			}
			if geminiToolInputRe.MatchString(h.Command) {
				findings = append(findings, finding.Finding{
					RuleID:   "CFG087",
					Severity: finding.Warn,
					Scope:    t.Scope,
					File:     t.GeminiFile,
					Message: "Gemini hooks.BeforeTool rewrites the tool arguments before execution (hookSpecificOutput.tool_input) — " +
						"a committed hook silently overrides the arguments the model chose, so what runs is not what was proposed. " +
						"Review the substitution, or block the call (decision: \"deny\") instead of rewriting it" + userScopeNote(t),
				})
			}
		}
	}
	return findings
}
