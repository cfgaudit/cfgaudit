package rules

import (
	"regexp"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg021 struct{}

var CFG021 = &cfg021{}

func init() { All = append(All, CFG021) }

func (r *cfg021) ID() string { return "CFG021" }

// proxyEnvVars are env keys that route an MCP server's HTTP(S) traffic through a
// proxy. Pointed at attacker infrastructure they enable MITM and capture of
// secrets sent in request headers (Authorization, X-Api-Key, …).
var proxyEnvVars = map[string]bool{
	"HTTP_PROXY":  true,
	"HTTPS_PROXY": true,
	"ALL_PROXY":   true,
}

// proxyShellRefRe matches a value that is a single shell-variable reference
// (e.g. "$HTTP_PROXY"); such values inherit from the environment rather than
// hardcoding a literal endpoint, so they are not flagged.
var proxyShellRefRe = regexp.MustCompile(`^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$`)

// Check flags MCP servers whose env routes traffic through a non-loopback proxy.
// Covers both settings.json mcpServers and the project .mcp.json.
func (r *cfg021) Check(t *Target) []finding.Finding {
	var findings []finding.Finding
	for _, ref := range t.mcpServerRefs() {
		keys := make([]string, 0, len(ref.Server.Env))
		for k := range ref.Server.Env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if !proxyEnvVars[strings.ToUpper(k)] {
				continue
			}
			v := strings.TrimSpace(ref.Server.Env[k])
			if v == "" || proxyShellRefRe.MatchString(v) || proxyTargetsLoopback(v) {
				continue
			}
			findings = append(findings, finding.Finding{
				RuleID:   "CFG021",
				Severity: finding.Warn,
				File:     ref.File,
				Message: "mcpServers." + ref.Name + ".env sets " + k + "=\"" + v +
					"\" — routes the server's HTTP(S) traffic through a non-local proxy, which can MITM requests and capture secrets sent in headers; point it at a loopback address or remove it",
			})
		}
	}
	return findings
}

// proxyTargetsLoopback reports whether a proxy URL/host:port points at the local
// machine (localhost, 127.0.0.0/8, or ::1).
func proxyTargetsLoopback(v string) bool {
	h := v
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.LastIndex(h, "@"); i >= 0 {
		h = h[i+1:]
	}
	if i := strings.IndexAny(h, "/?"); i >= 0 {
		h = h[:i]
	}
	h = strings.TrimSpace(h)
	switch {
	case strings.HasPrefix(h, "["): // [::1] or [::1]:port
		if j := strings.Index(h, "]"); j >= 0 {
			h = h[1:j]
		}
	case strings.Count(h, ":") == 1: // host:port (single colon → not bare IPv6)
		h = h[:strings.IndexByte(h, ':')]
	}
	h = strings.ToLower(strings.TrimSpace(h))
	if h == "localhost" || h == "::1" {
		return true
	}
	return strings.HasPrefix(h, "127.")
}
