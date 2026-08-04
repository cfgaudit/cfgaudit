package rules

import (
	"path/filepath"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg096 struct{}

var CFG096 = &cfg096{}

func init() { All = append(All, CFG096) }

func (r *cfg096) ID() string { return "CFG096" }

// Check flags a committed Gemini CLI MCP server declared `trust: true`.
//
// Gemini's per-server trust flag removes the confirmation prompt for every tool
// that server exposes. Traced to the point of use rather than the schema
// (packages/core/src/tools/mcp-tool.ts):
//
//	if (this.cliConfig?.isTrustedFolder() && this.trust) {
//	  return false; // server is trusted, no confirmation needed
//	}
//
// Both files that can declare it are committable: `.gemini/settings.json`, and
// the `mcp_servers` block of a `.gemini/agents/*.md` agent definition, which
// Gemini's own docs call project-level and team-shared. An agent-declared server
// reaches the same tool constructor — local-executor.ts hands the definition's
// servers to `maybeDiscoverMcpServer`, which builds the tool with
// `mcpServerConfig.trust` — so the two paths converge here even though the
// settings-tier policy engine (policy/config.ts, TRUSTED_MCP_SERVER_PRIORITY)
// only ever reads `settings.mcpServers`.
//
// The message names the folder-trust condition rather than claiming an
// unconditional bypass. That condition is a real mitigation and it is the same
// one that gates a stdio server starting at all, but it is granted once per
// folder and thereafter covers every clone.
//
// **Gated on the source file.** `Trust` decodes from any MCP source now that it
// is on the shared MCPServer, but only Gemini declares it: a `trust` key in a
// `.mcp.json` or `.cursor/mcp.json` is inert, and reporting it would be a false
// positive. qwen-code is a Gemini fork and may accept the same key, but that is
// unverified, so its files are deliberately not included.
func (r *cfg096) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	for _, ref := range t.mcpServerRefs() {
		if !ref.Server.Trust || !isGeminiMCPSource(ref.File) {
			continue
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG096",
			Severity: finding.Error,
			Scope:    t.Scope,
			File:     ref.File,
			Message: "mcpServers." + ref.Name + " is declared trust: true — every tool that server exposes then runs with no confirmation prompt once the folder is trusted, so a committed declaration makes that decision for whoever opens the repo. Remove the flag and approve the server's tools when they are actually used" + userScopeNote(t),
		})
	}
	return findings
}

// isGeminiMCPSource reports whether an MCP server came from a file whose format
// declares the trust field: Gemini's settings.json, or an agent definition under
// .gemini/agents.
func isGeminiMCPSource(path string) bool {
	if path == "" {
		return false
	}
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	if filepath.Base(dir) == ".gemini" && strings.EqualFold(base, "settings.json") {
		return true
	}
	return filepath.Base(dir) == "agents" && filepath.Base(filepath.Dir(dir)) == ".gemini"
}
