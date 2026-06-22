package rules

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg010 struct{}

var CFG010 = &cfg010{}

func init() { All = append(All, CFG010) }

func (r *cfg010) ID() string { return "CFG010" }

// npmPackageRunners are commands whose first positional arg is an npm-style
// package spec, version-pinned with an `@<version>` suffix.
var npmPackageRunners = map[string]bool{
	"npx":  true,
	"pnpm": true,
	"yarn": true,
	"bunx": true,
}

// pyPackageRunners are Python package runners whose first positional arg is a
// package spec pinned with a PEP 508 specifier (`ruff==0.1.0`) or, for uvx, an
// `@<version>` suffix (`ruff@0.1.0`).
var pyPackageRunners = map[string]bool{
	"uvx":  true,
	"pipx": true,
}

// pep508PinRe matches a PEP 508 version specifier on a package spec —
// ruff==0.1.0, pkg>=1.2, pkg~=1.0, pkg!=2.0 — requiring a digit after the
// operator so a bare name never looks pinned.
var pep508PinRe = regexp.MustCompile(`(===|==|~=|!=|>=|<=|>|<)\s*\d`)

func (r *cfg010) Check(t *Target) []finding.Finding {
	var findings []finding.Finding
	for _, ref := range t.mcpServerRefs() {
		if msg := analyzeMCPVersionPin(ref.Server.Command, ref.Server.Args); msg != "" {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG010",
				Severity: finding.Warn,
				File:     ref.File,
				Message:  "mcpServers." + ref.Name + ": " + msg,
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
	npm, py := npmPackageRunners[runner], pyPackageRunners[runner]
	if !npm && !py {
		return ""
	}
	pkg := mcpPackageArg(runner, args)
	if pkg == "" || isPathLikeArg(pkg) {
		return ""
	}
	if py {
		// uvx also accepts the npm-style `pkg@version`, so check both grammars.
		if pep508PinRe.MatchString(pkg) || hasNpmVersionPin(pkg) {
			return ""
		}
		return "package \"" + pkg + "\" passed to " + runner + " has no version pin (e.g. \"" + pkg + "==1.2.3\") — supply-chain compromise propagates silently to every agent that loads this server"
	}
	if hasNpmVersionPin(pkg) {
		return ""
	}
	return "package \"" + pkg + "\" passed to " + runner + " has no @version pin — supply-chain compromise propagates silently to every agent that loads this server"
}

// mcpPackageArg returns the first positional argument that names a package. A
// runner subcommand is skipped so the package arg is found one position later:
// `dlx`/`exec` for pnpm/yarn, `run` for pipx (`pipx run <pkg>`).
func mcpPackageArg(runner string, args []string) string {
	for i, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if (runner == "pnpm" || runner == "yarn") && (a == "dlx" || a == "exec") {
			return firstPositional(args[i+1:])
		}
		if runner == "pipx" && a == "run" {
			return firstPositional(args[i+1:])
		}
		return a
	}
	return ""
}

// firstPositional returns the first non-flag argument, or "" if none.
func firstPositional(args []string) string {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return a
		}
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
