// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

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
		for _, msg := range analyzeMCPVersionPins(ref.Server.Command, ref.Server.Args) {
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

// analyzeMCPVersionPins reports every unpinned package named by a runner
// invocation: the run package itself plus any extra package installed through
// a repeated package flag (`npx --package/-p`, `uvx --with`).
func analyzeMCPVersionPins(command string, args []string) []string {
	for _, a := range args {
		if strings.HasSuffix(a, "@latest") || strings.HasSuffix(a, ":latest") {
			return []string{"argument \"" + a + "\" uses unpinned :latest/@latest tag — pin to an exact version to prevent silent supply-chain compromise"}
		}
	}

	runner := filepath.Base(command)
	npm, py := npmPackageRunners[runner], pyPackageRunners[runner]
	if !npm && !py {
		return nil
	}
	var msgs []string
	for _, pkg := range collectPackageSpecs(runner, args) {
		if isPathLikeArg(pkg) {
			continue
		}
		if py {
			// uvx also accepts the npm-style `pkg@version`, so check both grammars.
			if pep508PinRe.MatchString(pkg) || hasNpmVersionPin(pkg) {
				continue
			}
			msgs = append(msgs, "package \""+pkg+"\" passed to "+runner+" has no version pin (e.g. \""+pkg+"==1.2.3\") — supply-chain compromise propagates silently to every agent that loads this server")
			continue
		}
		if hasNpmVersionPin(pkg) {
			continue
		}
		msgs = append(msgs, "package \""+pkg+"\" passed to "+runner+" has no @version pin — supply-chain compromise propagates silently to every agent that loads this server")
	}
	return msgs
}

// packageFlagValue returns the package spec carried by an inline package flag
// for the runner: `--package=<spec>` / `-p=<spec>` for npm runners and
// `--with=<spec>` for uvx, or "" if a is not a package flag for that runner.
// The prefixes are runner-specific: `-p` is `--python` for uvx, so `uvx
// -p=3.12` must not be read as a package spec.
func packageFlagValue(runner, a string) string {
	var prefixes []string
	if npmPackageRunners[runner] {
		prefixes = append(prefixes, "--package=", "-p=")
	}
	if runner == "uvx" {
		prefixes = append(prefixes, "--with=")
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(a, prefix) {
			return strings.TrimPrefix(a, prefix)
		}
	}
	return ""
}

// collectPackageSpecs returns the run package (first positional, after any
// runner subcommand) plus every extra package named by a repeated package
// flag: `--package <spec>` / `-p <spec>` for npm runners and `--with <spec>`
// for uvx. Duplicates are dropped so a spec named twice is reported once.
//
// For npm runners the first positional is only a package when no package flag
// is present (`npx cowsay hi`). Once any `--package` / `-p` appears, the
// positional names the bin to execute from those packages (`npx -y -p
// @scope/pkg@1.2.3 pkg-bin`), so it is not a package and is skipped.
func collectPackageSpecs(runner string, args []string) []string {
	var specs []string
	seen := map[string]bool{}
	add := func(s string) {
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		specs = append(specs, s)
	}

	// Flags whose next argument is a package spec rather than a plain flag.
	valueNext := map[string]bool{}
	if npmPackageRunners[runner] {
		valueNext["--package"] = true
		valueNext["-p"] = true
	}
	if runner == "uvx" {
		valueNext["--with"] = true
	}

	// A package flag seen before the first positional marks the npm positional
	// as a bin command rather than a package. Only flags before the positional
	// count: an argument like `npx -y @acme/mcp-server -p 3000` passes `-p
	// 3000` to the server itself, so the run package must still be checked.
	npmRunAsCommand := false
	if npmPackageRunners[runner] {
		for i := 0; i < len(args); i++ {
			a := args[i]
			if a == "--package" || a == "-p" || strings.HasPrefix(a, "--package=") || strings.HasPrefix(a, "-p=") {
				npmRunAsCommand = true
				break
			}
			if valueNext[a] {
				i++ // skip the flag's value so it is not mistaken for a positional
				continue
			}
			if strings.HasPrefix(a, "-") {
				continue
			}
			// Runner subcommand: the run package comes one position later.
			if (runner == "pnpm" || runner == "yarn") && (a == "dlx" || a == "exec") {
				continue
			}
			if runner == "pipx" && a == "run" {
				continue
			}
			// First positional reached; later flags belong to the executed server.
			break
		}
	}

	for i := 0; i < len(args); i++ {
		a := args[i]
		if spec := packageFlagValue(runner, a); spec != "" {
			add(spec)
			continue
		}
		if valueNext[a] {
			if i+1 < len(args) {
				add(args[i+1])
			}
			i++ // consumed the flag value so it is not mistaken for the run package
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		// Runner subcommand: the run package comes one position later —
		// `dlx`/`exec` for pnpm/yarn, `run` for pipx (`pipx run <pkg>`).
		if (runner == "pnpm" || runner == "yarn") && (a == "dlx" || a == "exec") {
			continue
		}
		if runner == "pipx" && a == "run" {
			continue
		}
		if npmRunAsCommand {
			// positional is the bin to execute, not a package — stop here
			break
		}
		add(a) // first positional is the run package; later positionals are server args
		break
	}
	return specs
}

// mcpPackageArg returns the first positional argument that names a package. A
// runner subcommand is skipped so the package arg is found one position later:
// `dlx`/`exec` for pnpm/yarn, `run` for pipx (`pipx run <pkg>`). Shared with
// CFG059's typosquat check.
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
