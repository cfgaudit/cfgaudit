package rules

import (
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg052 struct{}

var CFG052 = &cfg052{}

func init() { All = append(All, CFG052) }

func (r *cfg052) ID() string { return "CFG052" }

// Check flags an MCP server name declared in more than one config source that
// Claude Code merges — its inline settings.json mcpServers and the project
// .mcp.json. When the same name appears in both, the effective definition is
// ambiguous: a repo-committed .mcp.json can redefine (shadow) a server the user
// trusts under a familiar name, pointing it at a different command/url.
//
// Scope: this is the statically-detectable subset. Tool-name shadowing *within*
// a server needs connecting to the server (out of scope), and a name shared
// across different agents' configs (e.g. Cursor vs Claude) is per-agent
// divergence, not a precedence conflict, so it is not flagged.
func (r *cfg052) Check(t *Target) []finding.Finding {
	// Collect the distinct source files each server name appears in, preserving
	// first-seen order of the files for stable messages.
	files := map[string][]string{}
	seen := map[string]map[string]bool{}
	for _, ref := range t.mcpServerRefs() {
		if seen[ref.Name] == nil {
			seen[ref.Name] = map[string]bool{}
		}
		if ref.File != "" && !seen[ref.Name][ref.File] {
			seen[ref.Name][ref.File] = true
			files[ref.Name] = append(files[ref.Name], ref.File)
		}
	}

	names := make([]string, 0, len(files))
	for name, srcs := range files {
		if len(srcs) >= 2 {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	var findings []finding.Finding
	for _, name := range names {
		srcs := files[name]
		findings = append(findings, finding.Finding{
			RuleID:   "CFG052",
			Severity: finding.Warn,
			File:     srcs[0],
			Message: "mcpServers." + name + " is declared in multiple MCP config sources (" + strings.Join(srcs, ", ") +
				") — the effective definition is ambiguous and one source can shadow another; keep each MCP server in a single source" + userScopeNote(t),
		})
	}
	return findings
}
