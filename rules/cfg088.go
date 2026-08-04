package rules

import (
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg088 struct{}

var CFG088 = &cfg088{}

func init() { All = append(All, CFG088) }

func (r *cfg088) ID() string { return "CFG088" }

// Check flags a Copilot `type: "http"` hook that POSTs to a non-loopback URL.
// An http hook sends the event payload — prompts, tool names and arguments — to
// whatever endpoint the config names, so a committed hook file declares an
// outbound channel for everyone who opens the repository. CFG038 catches the same
// thing when it is spelled as a shell command (`env | curl …`); it cannot see a
// channel declared as configuration rather than command text.
//
// `allowedEnvVars` escalates it. The field whitelists environment-variable names
// that may be expanded inside the `headers` values of this hook — so naming a
// credential-bearing variable is a stated intent to put that credential on the
// wire to the endpoint. (Copilot requires https:// once the field is set, which
// protects the value in transit but not from the endpoint itself.)
//
// Loopback URLs are silent: a hook talking to a local daemon is not an outbound
// channel. Hooks with no URL, and non-http hook types, are not this rule's
// business.
func (r *cfg088) Check(t *Target) []finding.Finding {
	findings := r.checkAgentHooks(t)
	return append(findings, r.checkContinueHooks(t)...)
}

// checkContinueHooks applies the same rule to a Continue settings file's hooks.
// Continue's "http" handler carries the identical url / headers / allowedEnvVars
// fields, so the channel it declares is the same one; only the nesting differs
// (matcher groups rather than a flat handler list).
func (r *cfg088) checkContinueHooks(t *Target) []finding.Finding {
	ch := t.ContinueHooks
	if ch == nil || ch.DisableAllHooks || len(ch.Hooks) == 0 {
		return nil
	}
	var findings []finding.Finding
	for _, event := range sortedKeys2(ch.Hooks) {
		for _, group := range ch.Hooks[event] {
			for _, h := range group.Hooks {
				findings = append(findings, httpHookFindings(t, "Continue hooks."+event, t.ContinueHooksFile, h.Type, h.URL, h.AllowedEnvVars)...)
			}
		}
	}
	return findings
}

func (r *cfg088) checkAgentHooks(t *Target) []finding.Finding {
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
		for _, h := range ah.Hooks[event] {
			findings = append(findings, httpHookFindings(t, t.AgentHooksKind+" hooks."+event, t.AgentHooksFile, h.Type, h.URL, h.AllowedEnvVars)...)
		}
	}
	return findings
}

// httpHookFindings builds the rule's findings for one handler, shared by the
// Copilot/Cursor and Continue paths because both declare the same channel with
// the same field names. A non-http handler, a handler with no URL, and a loopback
// URL all yield nothing: a hook talking to a local daemon is not an outbound
// channel.
func httpHookFindings(t *Target, loc, file, handlerType, rawURL string, allowedEnvVars []string) []finding.Finding {
	if !strings.EqualFold(strings.TrimSpace(handlerType), "http") {
		return nil
	}
	url := strings.TrimSpace(rawURL)
	if url == "" || proxyTargetsLoopback(url) {
		return nil
	}
	if vars := nonEmptyEnvVars(allowedEnvVars); len(vars) > 0 {
		return []finding.Finding{{
			RuleID:   "CFG088",
			Severity: finding.Error,
			Scope:    t.Scope,
			File:     file,
			Message: loc + " is an http hook to \"" + url + "\" whose allowedEnvVars permits " + strings.Join(vars, ", ") +
				" to be expanded into its request headers — a committed file that forwards named environment variables to a remote endpoint is an exfiltration channel declared in configuration. Remove the variables, or point the hook at a loopback address" + userScopeNote(t),
		}}
	}
	return []finding.Finding{{
		RuleID:   "CFG088",
		Severity: finding.Warn,
		Scope:    t.Scope,
		File:     file,
		Message: loc + " is an http hook to \"" + url +
			"\" — the event payload (prompt text, tool names and arguments) is sent to a non-loopback endpoint for everyone who opens the repository. Verify the endpoint is trusted, or point the hook at a loopback address" + userScopeNote(t),
	}}
}

// nonEmptyEnvVars returns the trimmed, non-empty entries of an allowedEnvVars
// list, preserving the order the config declares them in.
func nonEmptyEnvVars(vars []string) []string {
	out := make([]string, 0, len(vars))
	for _, v := range vars {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
