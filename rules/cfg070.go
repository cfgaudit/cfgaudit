package rules

import (
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg070 struct{}

var CFG070 = &cfg070{}

func init() { All = append(All, CFG070) }

func (r *cfg070) ID() string { return "CFG070" }

// Check flags an MCP server whose command is a repo-relative path — a committed
// in-repo executable/script that runs automatically when a developer opens the
// project (some agents launch project MCP servers without a per-server prompt),
// so anyone who clones the repo runs it (CVE-2025-54135 / -64109 / -61260).
// Covers settings.json mcpServers, .mcp.json, and the cross-agent MCP configs
// (.cursor/mcp.json, .vscode/mcp.json, …).
//
// Only the command itself is checked: the common, legitimate pattern is an
// interpreter/runner with a script in args (node ./dist/index.js, npx pkg) — the
// command there is "node"/"npx", not a path, so it is not flagged. An absolute
// path or a bare PATH-looked-up name is likewise not flagged.
func (r *cfg070) Check(t *Target) []finding.Finding {
	var findings []finding.Finding
	for _, ref := range t.mcpServerRefs() {
		if !isRepoLocalCommandPath(ref.Server.Command) {
			continue
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG070",
			Severity: finding.Warn,
			File:     ref.File,
			Message: "mcpServers." + ref.Name + " command \"" + strings.TrimSpace(ref.Server.Command) +
				"\" is a repo-relative path — a committed in-repo executable that runs automatically when the project is opened, so anyone who clones the repo runs it (CVE-2025-54135). Point command at a reviewed, absolute binary or a pinned package runner (e.g. npx)" + userScopeNote(t),
		})
	}
	return findings
}

// isRepoLocalCommandPath reports whether cmd is a relative path with a directory
// component (./x, ../x, scripts/x, scripts\x) — i.e. an executable inside the
// repo. Absolute paths (/usr/bin/x, C:\x, \\host\x), URLs, and bare PATH names
// (npx, node, my-server) return false.
func isRepoLocalCommandPath(cmd string) bool {
	c := strings.TrimSpace(cmd)
	if c == "" || strings.Contains(c, "://") {
		return false
	}
	if strings.HasPrefix(c, "/") || strings.HasPrefix(c, `\\`) {
		return false // POSIX-absolute or UNC
	}
	if len(c) >= 2 && c[1] == ':' {
		return false // Windows drive path (C:\… / C:/…)
	}
	return strings.ContainsAny(c, `/\`)
}
