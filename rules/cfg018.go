package rules

import (
	"regexp"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

type cfg018 struct{}

var CFG018 = &cfg018{}

func init() { All = append(All, CFG018) }

func (r *cfg018) ID() string { return "CFG018" }

// bindAllIPv4Re matches the all-interfaces address 0.0.0.0 as a dotted-quad
// delimited by non-digit/non-dot boundaries, so "0.0.0.0", "--host=0.0.0.0" and
// "0.0.0.0:3000" match while real networks like "10.0.0.0" or "100.0.0.0" do not.
var bindAllIPv4Re = regexp.MustCompile(`(^|[^\d.])0\.0\.0\.0([^\d.]|$)`)

// Check flags MCP servers that bind to all network interfaces ("NeighborJack").
// The bind address may appear in a launch argument (e.g. --host 0.0.0.0) or an
// env var (e.g. HOST=0.0.0.0). Covers both settings.json mcpServers and the
// project .mcp.json.
func (r *cfg018) Check(t *Target) []finding.Finding {
	var findings []finding.Finding
	for _, ref := range t.mcpServerRefs() {
		if loc := allInterfacesBind(ref.Server); loc != "" {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG018",
				Severity: finding.Warn,
				File:     ref.File,
				Message: "mcpServers." + ref.Name + " binds to all network interfaces (" + loc +
					") — exposes the server to anyone on the same LAN or network segment (\"NeighborJack\"); bind to 127.0.0.1 (loopback) instead",
			})
		}
	}
	return findings
}

// allInterfacesBind returns a human-readable location of the first all-interfaces
// bind address found in the server's args or env, or "" when none is present.
func allInterfacesBind(s parser.MCPServer) string {
	for _, a := range s.Args {
		if bindsAllInterfaces(a) {
			return "argument \"" + a + "\""
		}
	}
	keys := make([]string, 0, len(s.Env))
	for k := range s.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if bindsAllInterfaces(s.Env[k]) {
			return "env." + k + "=\"" + s.Env[k] + "\""
		}
	}
	return ""
}

// bindsAllInterfaces reports whether s is or contains an all-interfaces bind
// address: IPv4 0.0.0.0, bracketed IPv6 [::], or the bare IPv6 unspecified "::".
func bindsAllInterfaces(s string) bool {
	if bindAllIPv4Re.MatchString(s) {
		return true
	}
	if strings.Contains(s, "[::]") {
		return true
	}
	return strings.TrimSpace(s) == "::"
}
