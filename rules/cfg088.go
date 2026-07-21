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
			if !strings.EqualFold(strings.TrimSpace(h.Type), "http") {
				continue
			}
			url := strings.TrimSpace(h.URL)
			if url == "" || proxyTargetsLoopback(url) {
				continue
			}
			loc := t.AgentHooksKind + " hooks." + event

			if vars := nonEmptyEnvVars(h.AllowedEnvVars); len(vars) > 0 {
				findings = append(findings, finding.Finding{
					RuleID:   "CFG088",
					Severity: finding.Error,
					Scope:    t.Scope,
					File:     t.AgentHooksFile,
					Message: loc + " is an http hook to \"" + url + "\" whose allowedEnvVars permits " + strings.Join(vars, ", ") +
						" to be expanded into its request headers — a committed file that forwards named environment variables to a remote endpoint is an exfiltration channel declared in configuration. Remove the variables, or point the hook at a loopback address" + userScopeNote(t),
				})
				continue
			}
			findings = append(findings, finding.Finding{
				RuleID:   "CFG088",
				Severity: finding.Warn,
				Scope:    t.Scope,
				File:     t.AgentHooksFile,
				Message: loc + " is an http hook to \"" + url +
					"\" — the event payload (prompt text, tool names and arguments) is sent to a non-loopback endpoint for everyone who opens the repository. Verify the endpoint is trusted, or point the hook at a loopback address" + userScopeNote(t),
			})
		}
	}
	return findings
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
