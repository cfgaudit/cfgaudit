// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	neturl "net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

type cfg088 struct{}

var CFG088 = &cfg088{}

func init() { All = append(All, CFG088) }

func (r *cfg088) ID() string { return "CFG088" }

// Check flags a Claude Code, Copilot, Cursor or Continue `type: "http"` hook that POSTs to a non-loopback URL.
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
	findings := r.checkClaudeHooks(t)
	findings = append(findings, r.checkAgentHooks(t)...)
	return append(findings, r.checkContinueHooks(t)...)
}

// checkClaudeHooks applies the rule to Claude Code's own http handler, in a
// settings file, a plugin hooks.json or a subagent's frontmatter (#745). The
// fields are the same url, headers and allowedEnvVars. disableAllHooks, merged
// across the settings files as Claude Code merges it, switches them all off.
func (r *cfg088) checkClaudeHooks(t *Target) []finding.Finding {
	if t == nil || t.ClaudeHooksDisabled {
		return nil
	}
	var findings []finding.Finding
	for _, set := range claudeHookSets(t) {
		set.each(func(loc string, h parser.HookCommand) {
			findings = append(findings, httpHookFindings(t, loc, set.file, h.Type, h.URL, h.AllowedEnvVars)...)
		})
	}
	return findings
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
	var findings []finding.Finding
	if ah := t.AgentHooks; ah != nil && !ah.DisableAllHooks && len(ah.Hooks) > 0 {
		findings = append(findings, agentHTTPHooks(t, ah, t.AgentHooksKind, t.AgentHooksFile)...)
	}
	// Copilot custom-agent frontmatter hooks (#747).
	if ah := t.CopilotAgentHooks; ah != nil && len(ah.Hooks) > 0 {
		findings = append(findings, agentHTTPHooks(t, ah, "Copilot agent", t.CopilotAgentHooksFile)...)
	}
	return findings
}

// agentHTTPHooks reports the http handlers of a flat event → handlers table.
func agentHTTPHooks(t *Target, ah *parser.AgentHooks, kind, file string) []finding.Finding {
	events := make([]string, 0, len(ah.Hooks))
	for e := range ah.Hooks {
		events = append(events, e)
	}
	sort.Strings(events)

	var findings []finding.Finding
	for _, event := range events {
		for _, h := range ah.Hooks[event] {
			findings = append(findings, httpHookFindings(t, kind+" hooks."+event, file, h.Type, h.URL, h.AllowedEnvVars)...)
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
	if url == "" || proxyTargetsLoopback(url) || placeholderHookURL(url) {
		return nil
	}
	if vars := credentialEnvVars(allowedEnvVars); len(vars) > 0 {
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

// credentialEnvVars returns the allowedEnvVars entries whose names say they
// hold a credential (CFG007's *_TOKEN, *_SECRET, *_API_KEY, ... suffixes), in
// the order the config declares them. Forwarding USER or CLAUDE_PROJECT_DIR is
// not an exfiltration channel; 3 of the 6 real Claude Code files that set the
// field in a 101-file sample named only such variables (#745).
func credentialEnvVars(vars []string) []string {
	out := make([]string, 0, len(vars))
	for _, v := range vars {
		if v = strings.TrimSpace(v); v != "" && hasSecretSuffix(v) {
			out = append(out, v)
		}
	}
	return out
}

// placeholderHookURLRe matches the unfilled parts of a template URL:
// __HOOK_URL__, YOUR/WEBHOOK/URL, <your-endpoint>, {{ url }}.
var placeholderHookURLRe = regexp.MustCompile(`__[A-Z][A-Z0-9_]*__|\bYOUR[_/-]|<[^>]*>|\{\{`)

// placeholderHookURL reports whether url is not an endpoint a hook can post to:
// not an http(s) URL at all, a template, or a host under a name reserved for
// documentation (RFC 2606, RFC 6761), which is where example configs point. In
// a 101-file sample of Claude Code hooks, 10 of the 16 files with an http hook
// were such examples (#745).
func placeholderHookURL(url string) bool {
	if placeholderHookURLRe.MatchString(url) {
		return true
	}
	u, err := neturl.Parse(url)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return true
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	for _, d := range []string{"example.com", "example.net", "example.org"} {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	for _, tld := range []string{".example", ".invalid", ".test"} {
		if strings.HasSuffix(host, tld) {
			return true
		}
	}
	return false
}
