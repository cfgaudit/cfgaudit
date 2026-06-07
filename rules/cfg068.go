package rules

import (
	"net"
	"regexp"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg068 struct{}

var CFG068 = &cfg068{}

func init() { All = append(All, CFG068) }

func (r *cfg068) ID() string { return "CFG068" }

// credTemplateRe matches a template-placeholder syntax that expands to a value at
// runtime: {{X}}, ${X}, %{X}, <% X %>, __TOKEN__. On an auth header/env value
// that expansion is a real credential (CVE-2026-31951).
var credTemplateRe = regexp.MustCompile(`\{\{.+?\}\}|\$\{[^}]+\}|%\{[^}]+\}|<%.+?%>|__[A-Z][A-Z0-9_]+__`)

// authKeyTokens mark a header name or env key as carrying a credential. Matched
// against the key with separators removed, so X-Api-Key / API_KEY both hit APIKEY.
var authKeyTokens = []string{"AUTHORIZATION", "APIKEY", "TOKEN", "SECRET", "BEARER"}

var authKeySep = strings.NewReplacer("-", "", "_", "")

// Check flags an MCP server that forwards a templated credential (an auth header
// or auth-named env value using {{…}}/${…} placeholder syntax) to a non-loopback
// endpoint over cleartext (http/ws) or to a raw IP. At runtime the placeholder
// expands to a real secret sent to that endpoint; an attacker-committed config
// thereby exfiltrates the credential (CVE-2026-31951).
//
// Scoped to cleartext / raw-IP endpoints on purpose: a templated auth header to a
// remote TLS *hostname* is the legitimate way to authenticate to a hosted MCP
// server (cfgaudit can't tell a trusted host from an attacker's), and CFG049
// already warns on every remote MCP url. Covers settings.json mcpServers + .mcp.json.
func (r *cfg068) Check(t *Target) []finding.Finding {
	var findings []finding.Finding
	for _, ref := range t.mcpServerRefs() {
		if !mcpURLCleartextOrRawIP(ref.Server.URL) {
			continue
		}
		keys := templatedCredKeys(ref.Server.Headers, ref.Server.Env)
		if len(keys) == 0 {
			continue
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG068",
			Severity: finding.Error,
			File:     ref.File,
			Message: "mcpServers." + ref.Name + " forwards a templated credential (" + strings.Join(keys, ", ") +
				") to \"" + strings.TrimSpace(ref.Server.URL) + "\" — a non-loopback endpoint over cleartext or a raw IP. At runtime the placeholder expands to a real secret sent to this endpoint; if the config was attacker-committed this exfiltrates the credential (CVE-2026-31951). Use a trusted TLS/loopback endpoint, or remove the credential" + userScopeNote(t),
		})
	}
	return findings
}

// templatedCredKeys returns the auth header names and auth env keys whose value
// is a template placeholder, labelled by location and sorted.
func templatedCredKeys(headers, env map[string]string) []string {
	var keys []string
	for k, v := range headers {
		if isAuthKey(k) && credTemplateRe.MatchString(v) {
			keys = append(keys, "header "+k)
		}
	}
	for k, v := range env {
		if isAuthKey(k) && credTemplateRe.MatchString(v) {
			keys = append(keys, "env "+k)
		}
	}
	sort.Strings(keys)
	return keys
}

func isAuthKey(k string) bool {
	up := authKeySep.Replace(strings.ToUpper(strings.TrimSpace(k)))
	for _, tok := range authKeyTokens {
		if strings.Contains(up, tok) {
			return true
		}
	}
	return false
}

// mcpURLCleartextOrRawIP reports whether url is a non-loopback endpoint where
// forwarding a credential is unambiguous exfiltration: cleartext (http/ws)
// transport or a raw IP literal. A TLS hostname returns false.
func mcpURLCleartextOrRawIP(rawURL string) bool {
	v := strings.TrimSpace(rawURL)
	if v == "" || proxyShellRefRe.MatchString(v) {
		return false
	}
	host := endpointHost(v)
	if host == "" || strings.Contains(host, "$") {
		return false // env-interpolated host: can't classify
	}
	if proxyTargetsLoopback(v) {
		return false
	}
	scheme := ""
	if i := strings.Index(v, "://"); i >= 0 {
		scheme = strings.ToLower(v[:i])
	}
	return scheme == "http" || scheme == "ws" || net.ParseIP(host) != nil
}
