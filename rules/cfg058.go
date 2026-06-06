package rules

import (
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg058 struct{}

var CFG058 = &cfg058{}

func init() { All = append(All, CFG058) }

func (r *cfg058) ID() string { return "CFG058" }

// Check flags an MCP server declared with the deprecated HTTP+SSE transport
// (type: "sse"). The MCP specification has superseded standalone SSE with
// Streamable HTTP, and SSE carries weaker properties — a long-lived
// unidirectional channel without resumability and the DNS-rebinding / Origin-
// validation footguns that affect HTTP-based MCP transports (AISVS C10.3, which
// restricts SSE to local/tightly-controlled use). Unlike CFG049, which keys on
// the url (cleartext / non-loopback host), this rule keys on the transport
// choice itself, so it fires even for a TLS or loopback SSE server. Covers every
// MCP source in scope (settings.json mcpServers, .mcp.json, cross-agent configs).
func (r *cfg058) Check(t *Target) []finding.Finding {
	var findings []finding.Finding
	for _, ref := range t.mcpServerRefs() {
		if !strings.EqualFold(strings.TrimSpace(ref.Server.Type), "sse") {
			continue
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG058",
			Severity: finding.Warn,
			File:     ref.File,
			Message: "mcpServers." + ref.Name + " uses the deprecated MCP transport type \"sse\" — the spec has superseded standalone HTTP+SSE with Streamable HTTP, which has stronger transport guarantees (SSE lacks resumability and shares the DNS-rebinding/Origin-validation pitfalls of HTTP MCP). Switch to type \"http\" (Streamable HTTP); keep any remaining SSE server on a loopback / tightly-controlled channel",
		})
	}
	return findings
}
