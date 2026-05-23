package rules

import "github.com/cfgaudit/cfgaudit/internal/finding"

type cfg017 struct{}

var CFG017 = &cfg017{}

func init() { All = append(All, CFG017) }

func (r *cfg017) ID() string { return "CFG017" }

// Check flags any MCP server with dangerouslyAllowBrowser: true. The server then
// accepts browser-originated requests, which combined with DNS rebinding exposed
// the Anthropic MCP Inspector to unauthenticated RCE with filesystem access from
// any website the user visited (CVE-2025-49596, CVSS 9.4). Covers both inline
// settings.json mcpServers and the project .mcp.json.
func (r *cfg017) Check(t *Target) []finding.Finding {
	var findings []finding.Finding
	for _, ref := range t.mcpServerRefs() {
		if !ref.Server.DangerouslyAllowBrowser {
			continue
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG017",
			Severity: finding.Error,
			File:     ref.File,
			Message:  "mcpServers." + ref.Name + " sets dangerouslyAllowBrowser: true — the server accepts browser-originated requests, opening a DNS-rebinding path to unauthenticated RCE from any site the user visits (CVE-2025-49596). Remove the flag, or bind the server to loopback and enforce Origin checks",
		})
	}
	return findings
}
