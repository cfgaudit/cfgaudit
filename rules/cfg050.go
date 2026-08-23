package rules

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

type cfg050 struct{}

var CFG050 = &cfg050{}

func init() { All = append(All, CFG050) }

func (r *cfg050) ID() string { return "CFG050" }

// authHeaderNames are request-header names whose value is a credential. They
// don't match the CFG007 *_TOKEN/_SECRET key-name heuristic, so they are matched
// explicitly (case-insensitively).
var authHeaderNames = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"x-api-key":           true,
	"api-key":             true,
	"apikey":              true,
	"x-auth-token":        true,
	"x-auth":              true,
	"x-access-token":      true,
	"authentication":      true,
}

// authSchemeRe strips a leading auth scheme word (Bearer/Basic/Token) so the
// remaining credential can be checked for placeholder/shell-ref exemption.
//
// The trailing alternation matches end-of-string as well as whitespace, so a
// value that is nothing but the scheme word leaves an empty credential and is
// skipped. Real configs do carry that: four header values in a 108-file Continue
// sample are a bare "Basic", which names an auth scheme and holds no secret.
var authSchemeRe = regexp.MustCompile(`^(?i:bearer|basic|token)(?:\s+|$)`)

// literalQuotes are the characters a doubly-quoted YAML or JSON string leaves
// around its own value. They are not part of the credential, and leaving them on
// defeats both the scheme strip and the placeholder checks.
const literalQuotes = "'\"`"

// placeholderRe matches obvious non-secret placeholder values that should not be
// flagged (e.g. "<your-token>", "changeme", "xxxxx", "TODO").
var placeholderRe = regexp.MustCompile(`(?i)^(<.*>|x{3,}|changeme|your[-_ ].*|todo|placeholder|example|\.\.\.)$`)

// Check flags hardcoded secrets in an MCP server's env or headers block — the
// MCP analogue of CFG007 (which only covers settings.json env). Covers every MCP
// source in scope, plus the headers of a Copilot `type: "http"` hook, which are
// the same shape of committed request credential. Shares CFG007's secret detector
// for values and key names.
func (r *cfg050) Check(t *Target) []finding.Finding {
	findings := r.checkAgentHookHeaders(t)
	findings = append(findings, r.checkMarketplaceHeaders(t)...)
	findings = append(findings, r.checkContinueRequestOptions(t)...)
	findings = append(findings, r.checkZedEnv(t)...)
	for _, ref := range t.mcpServerRefs() {
		base := "mcpServers." + ref.Name

		for _, k := range sortedKeys(ref.Server.Env) {
			v := strings.TrimSpace(ref.Server.Env[k])
			if v == "" || isSecretReference(v) {
				continue
			}
			if label, ok := matchSecretPattern(v); ok {
				findings = append(findings, secretFinding(base+".env."+k, "a hardcoded "+label, ref.File, t))
			} else if hasSecretSuffix(k) {
				findings = append(findings, secretFinding(base+".env."+k, "a secret-like name with a literal value", ref.File, t))
			}
		}

		findings = append(findings, headerSecrets(base, ref.Server.Headers, ref.File, t)...)
	}
	return findings
}

// checkAgentHookHeaders reports hardcoded credentials in the headers of a Cursor
// or Copilot `type: "http"` hook. The channel itself is CFG088's finding; a
// literal secret sitting in its headers is the same problem CFG050 already
// reports for an MCP server, in a different committed file.
//
// disableAllHooks does not suppress this one: a secret committed into a file is
// leaked whether or not the agent currently runs the hook.
func (r *cfg050) checkAgentHookHeaders(t *Target) []finding.Finding {
	ah := t.AgentHooks
	if ah == nil || len(ah.Hooks) == 0 {
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
			if len(h.Headers) == 0 {
				continue
			}
			base := t.AgentHooksKind + " hooks." + event
			findings = append(findings, headerSecrets(base, h.Headers, t.AgentHooksFile, t)...)
		}
	}
	return findings
}

// checkMarketplaceHeaders reports hardcoded credentials in the request headers of
// an extraKnownMarketplaces entry. CFG055 already reports the registration
// itself; a literal secret in its headers is CFG050's problem, at a third
// committed source after MCP servers and agent hooks.
//
// Those headers are really sent. Upstream: "If you register the marketplace from
// a URL source with headers, such as an extraKnownMarketplaces entry, Claude Code
// sends those headers with archive downloads whose URL shares the marketplace
// URL's origin." Claude Code 2.1.231 carries the matching guard string, "Fetch of
// … redirected to a different origin; dropped inherited marketplace headers", so
// the inheritance is real and bounded to same-origin fetches.
//
// Unlike CFG055 this is not scoped to project settings. A secret written into a
// user's own settings.json is still a secret in a plaintext file, which is how
// CFG050 already treats an MCP server's headers.
func (r *cfg050) checkMarketplaceHeaders(t *Target) []finding.Finding {
	if t == nil || t.Settings == nil {
		return nil
	}
	raw, key := t.Settings.Marketplaces()
	if len(raw) == 0 {
		return nil
	}
	var entries map[string]struct {
		Source struct {
			Headers map[string]string `json:"headers"`
		} `json:"source"`
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil // a shape this version does not model
	}
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)

	var findings []finding.Finding
	for _, name := range names {
		headers := entries[name].Source.Headers
		if len(headers) == 0 {
			continue
		}
		findings = append(findings, headerSecrets(key+"."+name+".source", headers, t.SettingsFile, t)...)
	}
	return findings
}

// checkContinueRequestOptions reports hardcoded credentials in a Continue
// config.yaml: the headers of any requestOptions block, and the apiKey of a data
// entry.
//
// requestOptions is the shared schema that hangs off models, mcpServers and data
// alike, and it is where the credentials actually are. Across 108 real
// .continue/config.yaml files it appears 44 times (42 on models), against 1 for
// the whole data block, so pointing the detector only at data would have covered
// the smaller half of the issue that asked for it.
//
// The models' own apiKey is already reported elsewhere in the Continue coverage;
// only the data entry's is added here, since nothing read that block before.
func (r *cfg050) checkContinueRequestOptions(t *Target) []finding.Finding {
	if t == nil || t.Continue == nil {
		return nil
	}
	var findings []finding.Finding
	add := func(base string, ro *parser.ContinueRequestOptions) {
		if ro == nil || len(ro.Headers) == 0 {
			return
		}
		findings = append(findings, headerSecrets(base, ro.Headers, t.ContinueFile, t)...)
	}

	for i, m := range t.Continue.Models {
		add("Continue models["+continueLabel(i, m.Name)+"].requestOptions", m.RequestOptions)
	}
	for i, s := range t.Continue.MCPServers {
		add("Continue mcpServers["+continueLabel(i, s.Name)+"].requestOptions", s.RequestOptions)
	}
	for i, d := range t.Continue.Data {
		base := "Continue data[" + continueLabel(i, d.Name) + "]"
		add(base+".requestOptions", d.RequestOptions)

		v := strings.TrimSpace(d.APIKey)
		if v == "" || isSecretReference(v) {
			continue
		}
		what := "a hardcoded credential"
		if label, ok := matchSecretPattern(v); ok {
			what = "a hardcoded " + label
		} else if screamingPlaceholderRe.MatchString(v) {
			continue // an unfilled template
		}
		findings = append(findings, secretFinding(base+".apiKey", what, t.ContinueFile, t))
	}
	return findings
}

// continueLabel renders a list entry as its name when it has one, so a finding
// points at something a reader can find in the file, and falls back to the index.
func continueLabel(i int, name string) string {
	if n := strings.TrimSpace(name); n != "" {
		return "\"" + n + "\""
	}
	return strconv.Itoa(i)
}

// checkZedEnv reports hardcoded credentials in the environment blocks a Zed
// .zed/settings.json attaches to the programs it launches: terminal.env,
// lsp.<name>.binary.env and dap.<name>.env. Same shape and same detectors as an
// MCP server's env, which CFG050 has always read.
//
// One real config in a 307-file sample carries SURREALDB_PASSWORD in
// terminal.env, so this is not a hypothetical block.
func (r *cfg050) checkZedEnv(t *Target) []finding.Finding {
	if t == nil || t.ZedSettings == nil {
		return nil
	}
	var findings []finding.Finding
	for _, site := range t.ZedSettings.CommandSites() {
		for _, k := range sortedKeys(site.Env) {
			v := unquoteValue(strings.TrimSpace(site.Env[k]))
			if v == "" || isSecretReference(v) {
				continue
			}
			loc := "Zed " + site.Label + ".env." + k
			if label, ok := matchSecretPattern(v); ok {
				findings = append(findings, secretFinding(loc, "a hardcoded "+label, t.ZedSettingsFile, t))
			} else if hasSecretSuffix(k) && !screamingPlaceholderRe.MatchString(v) {
				findings = append(findings, secretFinding(loc, "a secret-like name with a literal value", t.ZedSettingsFile, t))
			}
		}
	}
	return findings
}

// headerSecrets reports hardcoded credentials in a request-header block, by
// value pattern (a recognised token shape) or by header name (an auth header
// carrying a literal, non-placeholder credential).
func headerSecrets(base string, headers map[string]string, file string, t *Target) []finding.Finding {
	var findings []finding.Finding
	for _, k := range sortedKeys(headers) {
		v := unquoteValue(strings.TrimSpace(headers[k]))
		if v == "" || isSecretReference(v) {
			continue
		}
		if label, ok := matchSecretPattern(v); ok {
			findings = append(findings, secretFinding(base+".headers."+k, "a hardcoded "+label, file, t))
			continue
		}
		// An auth header carrying a literal (non-placeholder) credential.
		if authHeaderNames[strings.ToLower(k)] {
			cred := strings.TrimSpace(authSchemeRe.ReplaceAllString(v, ""))
			if cred == "" || isSecretReference(cred) || placeholderRe.MatchString(cred) {
				continue
			}
			if screamingPlaceholderRe.MatchString(cred) {
				continue // an unfilled template such as "TU_API_KEY_AQUI"
			}
			what := "a hardcoded credential"
			if label, ok := matchSecretPattern(cred); ok {
				what = "a hardcoded " + label
			}
			findings = append(findings, secretFinding(base+".headers."+k, what, file, t))
		}
	}
	return findings
}

// unquoteValue removes one layer of literal surrounding quotes. A value that is
// merely quoted is the same value; a value that is not quoted is returned as is.
// RE2 has no backreferences, so the matching pair is checked directly.
func unquoteValue(v string) string {
	if len(v) < 2 || v[0] != v[len(v)-1] || !strings.ContainsRune(literalQuotes, rune(v[0])) {
		return v
	}
	return strings.TrimSpace(v[1 : len(v)-1])
}

func secretFinding(loc, what, file string, t *Target) finding.Finding {
	return finding.Finding{
		RuleID:   "CFG050",
		Severity: finding.Error,
		File:     file,
		Message:  loc + " contains " + what + " — do not commit secrets to an agent config file; reference an environment variable (e.g. \"${TOKEN}\") instead" + userScopeNote(t),
	}
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
