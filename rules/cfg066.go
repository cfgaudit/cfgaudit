package rules

import (
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg066 struct{}

var CFG066 = &cfg066{}

func init() { All = append(All, CFG066) }

func (r *cfg066) ID() string { return "CFG066" }

// corsOriginKeys are env keys that HTTP-transport MCP servers read as their CORS
// allow-origin policy. A wildcard value lets any web page issue cross-origin
// requests to the server (CVE-2026-33010).
var corsOriginKeys = map[string]bool{
	"CORS_ORIGINS":                true,
	"CORS_ALLOW_ORIGIN":           true,
	"ALLOWED_ORIGINS":             true,
	"ALLOW_ORIGINS":               true,
	"MCP_CORS_ORIGINS":            true,
	"ACCESS_CONTROL_ALLOW_ORIGIN": true,
}

// anonAccessEnableKeys are env keys that, when truthy, disable authentication on
// an MCP server; authRequireKeys disable it when falsy.
var (
	anonAccessEnableKeys = map[string]bool{
		"MCP_ALLOW_ANONYMOUS_ACCESS": true,
		"ALLOW_ANONYMOUS":            true,
		"ANONYMOUS_ACCESS":           true,
		"AUTH_DISABLED":              true,
		"DISABLE_AUTH":               true,
		"NO_AUTH":                    true,
	}
	authRequireKeys = map[string]bool{
		"REQUIRE_AUTH":  true,
		"AUTH_REQUIRED": true,
		"AUTH_ENABLED":  true,
	}
)

// Check flags MCP servers whose env sets a wildcard CORS allow-origin policy —
// any web page can then issue cross-origin requests to the server. Warn on its
// own; error when the same env also disables authentication, since any site can
// then read or manipulate the server's data unauthenticated (CVE-2026-33010).
// Covers both settings.json mcpServers and the project .mcp.json.
func (r *cfg066) Check(t *Target) []finding.Finding {
	var findings []finding.Finding
	for _, ref := range t.mcpServerRefs() {
		key := wildcardCorsKey(ref.Server.Env)
		if key == "" {
			continue
		}
		if anonymousAccessEnabled(ref.Server.Env) {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG066",
				Severity: finding.Error,
				File:     ref.File,
				Message: "mcpServers." + ref.Name + ".env sets a wildcard CORS origin (" + key +
					"=*) together with anonymous access — any web page the user visits can read and manipulate this MCP server's data unauthenticated (CVE-2026-33010). Restrict the allowed origins and require authentication",
			})
			continue
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG066",
			Severity: finding.Warn,
			File:     ref.File,
			Message: "mcpServers." + ref.Name + ".env sets a wildcard CORS origin (" + key +
				"=*) — any web page can issue cross-origin requests to this MCP server. Restrict it to the specific origins that need access",
		})
	}
	return findings
}

// wildcardCorsKey returns the first (sorted) CORS-origin env key whose value
// contains a bare "*" wildcard, or "".
func wildcardCorsKey(env map[string]string) string {
	var keys []string
	for k, v := range env {
		if corsOriginKeys[strings.ToUpper(strings.TrimSpace(k))] && hasWildcardOrigin(v) {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return ""
	}
	sort.Strings(keys)
	return keys[0]
}

// hasWildcardOrigin reports whether a comma/space-separated origin list contains
// a bare "*" token.
func hasWildcardOrigin(v string) bool {
	for _, tok := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		if tok == "*" {
			return true
		}
	}
	return false
}

// anonymousAccessEnabled reports whether the env disables authentication via a
// truthy anon-enable key or a falsy auth-require key.
func anonymousAccessEnabled(env map[string]string) bool {
	for k, v := range env {
		up := strings.ToUpper(strings.TrimSpace(k))
		if anonAccessEnableKeys[up] && isTruthy(v) {
			return true
		}
		if authRequireKeys[up] && isFalsy(v) {
			return true
		}
	}
	return false
}

func isTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}

func isFalsy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "false", "0", "no", "off":
		return true
	}
	return false
}
