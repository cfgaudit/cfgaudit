package rules

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg010 struct{}

var CFG010 = &cfg010{}

func init() { All = append(All, CFG010) }

func (r *cfg010) ID() string { return "CFG010" }

// npmPackageRunners are commands whose first positional arg is an npm-style package spec.
var npmPackageRunners = map[string]bool{
	"npx":  true,
	"pnpm": true,
	"yarn": true,
	"bunx": true,
}

func (r *cfg010) Check(t *Target) []finding.Finding {
	if t.Settings == nil || len(t.Settings.MCPServers) == 0 {
		return nil
	}
	names := make([]string, 0, len(t.Settings.MCPServers))
	for n := range t.Settings.MCPServers {
		names = append(names, n)
	}
	sort.Strings(names)

	var findings []finding.Finding
	for _, name := range names {
		s := t.Settings.MCPServers[name]
		if msg := analyzeMCPVersionPin(s.Command, s.Args); msg != "" {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG010",
				Severity: finding.Warn,
				File:     t.SettingsFile,
				Message:  "mcpServers." + name + ": " + msg,
			})
		}
	}
	return findings
}

func analyzeMCPVersionPin(command string, args []string) string {
	for _, a := range args {
		if strings.HasSuffix(a, "@latest") || strings.HasSuffix(a, ":latest") {
			return "argument \"" + a + "\" uses unpinned :latest/@latest tag — pin to an exact version to prevent silent supply-chain compromise"
		}
	}

	runner := filepath.Base(command)
	if !npmPackageRunners[runner] {
		return ""
	}
	pkg := mcpPackageArg(runner, args)
	if pkg == "" || isPathLikeArg(pkg) {
		return ""
	}
	if hasNpmVersionPin(pkg) {
		return ""
	}
	return "package \"" + pkg + "\" passed to " + runner + " has no @version pin — supply-chain compromise propagates silently to every agent that loads this server"
}

// mcpPackageArg returns the first positional argument that names a package.
// For pnpm/yarn the `dlx`/`exec` subcommand is skipped so the package arg is found one position later.
func mcpPackageArg(runner string, args []string) string {
	for i, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if (runner == "pnpm" || runner == "yarn") && (a == "dlx" || a == "exec") {
			for _, b := range args[i+1:] {
				if strings.HasPrefix(b, "-") {
					continue
				}
				return b
			}
			return ""
		}
		return a
	}
	return ""
}

// hasNpmVersionPin reports whether an npm-style package spec includes an `@<version>` suffix.
// `@scope/name` (scoped, no version) returns false; `@scope/name@1.2.3` returns true.
func hasNpmVersionPin(pkg string) bool {
	rest := pkg
	if strings.HasPrefix(pkg, "@") {
		rest = pkg[1:]
	}
	return strings.Contains(rest, "@")
}

func isPathLikeArg(s string) bool {
	return strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../") || strings.HasPrefix(s, "/")
}
