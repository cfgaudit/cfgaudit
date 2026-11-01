// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"os"
	"path/filepath"
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
		cmd := strings.TrimSpace(ref.Server.Command)
		if buildOutputPath(cmd) && !commandInTree(t, ref.File, cmd) {
			// #1211: a build or install output directory is not in a fresh
			// clone; the developer builds or installs the binary first, and
			// CFG047/CFG067 report how a build is triggered.
			findings = append(findings, finding.Finding{
				RuleID:   "CFG070",
				Severity: finding.Info,
				File:     ref.File,
				Message: "mcpServers." + ref.Name + " command \"" + cmd +
					"\" runs a locally built or installed binary; it is not in the repository, so check how it is built before you start the server" + userScopeNote(t),
			})
			continue
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG070",
			Severity: finding.Warn,
			File:     ref.File,
			Message: "mcpServers." + ref.Name + " command \"" + cmd +
				"\" is a repo-relative path — a committed in-repo executable that runs automatically when the project is opened, so anyone who clones the repo runs it (CVE-2025-54135). Point command at a reviewed, absolute binary or a pinned package runner (e.g. npx)" + userScopeNote(t),
		})
	}
	return findings
}

// buildOutputPrefixes are directories a build or package install creates,
// which a fresh clone does not contain (#1211).
var buildOutputPrefixes = []string{"target/", ".venv/", "venv/", "vendor/bin/", "node_modules/.bin/", "build/", "dist/"}

// buildOutputPath reports whether the command's path starts with a build or
// install output directory.
func buildOutputPath(cmd string) bool {
	p := commandPath(cmd)
	for _, pre := range buildOutputPrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// commandPath is the command's executable with / separators and without a
// leading ./.
func commandPath(cmd string) string {
	if i := strings.IndexAny(cmd, " \t"); i >= 0 {
		cmd = cmd[:i]
	}
	p := strings.ReplaceAll(cmd, `\`, "/")
	for strings.HasPrefix(p, "./") {
		p = p[2:]
	}
	return p
}

// commandInTree reports whether the command's file is in the scanned tree,
// resolved from the project directory or from the MCP config file's
// directory and its parent. A committed file under an output prefix (a
// vendor/bin script checked into git) keeps the warning.
func commandInTree(t *Target, file, cmd string) bool {
	p := filepath.FromSlash(commandPath(cmd))
	dirs := []string{filepath.Dir(file), filepath.Dir(filepath.Dir(file))}
	if t.ProjectDir != "" {
		dirs = append([]string{t.ProjectDir}, dirs...)
	}
	for _, d := range dirs {
		if _, err := os.Lstat(filepath.Join(d, p)); err == nil {
			return true
		}
	}
	return false
}

// isRepoLocalCommandPath reports whether cmd is a relative path with a directory
// component (./x, ../x, scripts/x, scripts\x) — i.e. an executable inside the
// repo. Absolute paths (/usr/bin/x, C:\x, \\host\x), env/home expansions
// (${HOME}/x, ~/x), URLs, and bare PATH names (npx, node, my-server) return false.
func isRepoLocalCommandPath(cmd string) bool {
	c := strings.TrimSpace(cmd)
	if c == "" {
		return false
	}
	// Consider only the executable (first whitespace-separated token): a value
	// like "npx -y @scope/pkg" is the runner npx, and the "/" is in the package
	// name, not a path separator.
	if i := strings.IndexAny(c, " \t"); i >= 0 {
		c = c[:i]
	}
	if c == "" || strings.Contains(c, "://") {
		return false
	}
	if strings.HasPrefix(c, "$") || strings.HasPrefix(c, "~") {
		return false // env / home expansion — resolves outside the repo
	}
	if strings.HasPrefix(c, "/") || strings.HasPrefix(c, `\\`) {
		return false // POSIX-absolute or UNC
	}
	if len(c) >= 2 && c[1] == ':' {
		return false // Windows drive path (C:\… / C:/…)
	}
	return strings.ContainsAny(c, `/\`)
}
