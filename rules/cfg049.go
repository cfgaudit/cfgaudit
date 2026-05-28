package rules

import (
	"net"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg049 struct{}

var CFG049 = &cfg049{}

func init() { All = append(All, CFG049) }

func (r *cfg049) ID() string { return "CFG049" }

// Check flags remote (HTTP/SSE/WebSocket) MCP servers whose url points at a
// non-loopback host — a repo-controlled config can route the agent's context and
// header secrets to an attacker endpoint (the MCP analogue of CFG005/CFG046).
// Severity:
//   - error: cleartext transport (http:// / ws://) to a non-loopback host —
//     credentials/context sent unencrypted; or a raw IP literal (a hardcoded
//     external endpoint).
//   - warn:  TLS transport to a non-loopback hostname.
//
// Loopback urls, empty values, and shell-variable references are exempt. Covers
// every MCP source in scope (settings.json, .mcp.json, other agents' configs).
func (r *cfg049) Check(t *Target) []finding.Finding {
	var findings []finding.Finding
	for _, ref := range t.mcpServerRefs() {
		v := strings.TrimSpace(ref.Server.URL)
		if v == "" || proxyShellRefRe.MatchString(v) {
			continue
		}
		host := endpointHost(v)
		if host == "" || strings.Contains(host, "$") { // env-interpolated host: can't classify
			continue
		}
		if proxyTargetsLoopback(v) {
			continue
		}

		scheme := ""
		if i := strings.Index(v, "://"); i >= 0 {
			scheme = strings.ToLower(v[:i])
		}
		cleartext := scheme == "http" || scheme == "ws"
		rawIP := net.ParseIP(host) != nil

		sev := finding.Warn
		detail := "a non-loopback host — verify it is a trusted endpoint, or point it at a loopback address"
		switch {
		case cleartext:
			sev = finding.Error
			detail = "a non-loopback host over cleartext " + scheme + ":// — context and header secrets are sent unencrypted; use https/wss or a loopback address"
		case rawIP:
			sev = finding.Error
			detail = "a raw IP — a hardcoded external endpoint; verify it is trusted or remove it"
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG049",
			Severity: sev,
			File:     ref.File,
			Message: "mcpServers." + ref.Name + " connects to \"" + v +
				"\" — " + detail + userScopeNote(t),
		})
	}
	return findings
}
