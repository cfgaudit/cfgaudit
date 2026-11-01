// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"net"
	"net/url"
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
//   - info:  TLS transport to an endpoint a vendor documents for its own
//     service (mcpvendors.go, #1202).
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
		if proxyTargetsLoopback(v) || localhostSubdomain(v) {
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
		default:
			if vendor, ok := knownMCPVendor(v); ok {
				sev = finding.Info
				detail = "the MCP endpoint " + vendor.vendor + " documents for its service (" + vendor.doc + "); it still receives the context and headers the agent sends, so keep it only if the project uses " + vendor.vendor
			}
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

// localhostSubdomain reports whether a URL's host is a subdomain of localhost
// (my-app.localhost), which RFC 6761 reserves for loopback (#1202). Measured
// on Linux: getaddrinfo, Node 24 (dns.lookup, behind Claude Code, Gemini CLI,
// Qwen Code, Copilot CLI and VS Code), Python 3 and Go 1.26 all resolve it to
// 127.0.0.1 and ::1, and systemd-resolved answers it as synthetic data, with no
// query sent out. The host is taken from net/url, so a name that only appears
// after an @ in the path does not count.
func localhostSubdomain(v string) bool {
	u, err := url.Parse(strings.TrimSpace(v))
	if err != nil || u.Host == "" {
		return false
	}
	return strings.HasSuffix(strings.ToLower(u.Hostname()), ".localhost")
}
