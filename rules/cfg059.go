package rules

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg059 struct{}

var CFG059 = &cfg059{}

func init() { All = append(All, CFG059) }

func (r *cfg059) ID() string { return "CFG059" }

// Check flags MCP servers whose npm package or remote host is suspiciously
// similar — but not identical — to a known-good MCP identifier (see cfg059_data).
// A typosquatted package executes arbitrary code the moment the server starts,
// and a lookalike endpoint intercepts the agent's context and credentials.
//
// Matching is precision-first to keep false positives down: an exact match is
// never flagged; a homoglyph substitution (0→o, 1→l, …) that folds onto an
// official identifier, or a single-character edit, is an error; a two-character
// edit or an official server name carried under a non-official npm scope is a
// warning. Residual false positives are suppressible via .cfgaudit-ignore.
func (r *cfg059) Check(t *Target) []finding.Finding {
	var findings []finding.Finding
	for _, ref := range t.mcpServerRefs() {
		runner := filepath.Base(ref.Server.Command)
		if npmPackageRunners[runner] {
			spec := mcpPackageArg(runner, ref.Server.Args)
			if spec != "" && !isPathLikeArg(spec) {
				if m := bestPackageSquat(spec); m != nil {
					findings = append(findings, finding.Finding{
						RuleID:   "CFG059",
						Severity: m.severity,
						File:     ref.File,
						Message: "mcpServers." + ref.Name + " package \"" + npmPackageName(spec) + "\" is suspiciously similar to the official \"" + m.official +
							"\" (" + m.reason + ") — a typosquatted MCP package runs arbitrary code on server start. Verify the exact package name; suppress via .cfgaudit-ignore if intentional",
					})
					continue // one finding per server
				}
			}
		}

		host := strings.TrimSpace(endpointHost(ref.Server.URL))
		if host != "" && !strings.Contains(host, "$") {
			if m := bestSquat(host, knownMCPHosts); m != nil {
				findings = append(findings, finding.Finding{
					RuleID:   "CFG059",
					Severity: m.severity,
					File:     ref.File,
					Message: "mcpServers." + ref.Name + " endpoint host \"" + host + "\" is suspiciously similar to \"" + m.official +
						"\" (" + m.reason + ") — a lookalike MCP endpoint can intercept the agent's context and credentials. Verify the host; suppress via .cfgaudit-ignore if intentional",
				})
			}
		}
	}

	// Hook (and other command-bearing) sites can run an npm package via a runner
	// too — a prompt-injected or repo-committed `npx <typosquat>` executes arbitrary
	// code the same way an MCP launcher does. Scan every command site uniformly.
	for _, site := range commandSites(t) {
		seen := map[string]bool{}
		for _, spec := range hookNpmPackageSpecs(site.Command) {
			name := npmPackageName(spec)
			if seen[name] {
				continue
			}
			seen[name] = true
			if m := bestSquat(name, knownHookToolPackages); m != nil {
				findings = append(findings, finding.Finding{
					RuleID:   "CFG059",
					Severity: m.severity,
					File:     site.File,
					Message: site.Label + " runs npm package \"" + name + "\" which is suspiciously similar to \"" + m.official +
						"\" (" + m.reason + ") — a typosquatted package runs arbitrary code the moment the hook fires. Verify the exact package name; suppress via .cfgaudit-ignore if intentional" + userScopeNote(t),
				})
			}
		}
	}
	return findings
}

// shellSegmentRe splits a hook command string at the shell operators that separate
// independent commands (&&, ||, |, ;, &, newline), so a runner invocation anywhere
// in a chain like `eslint . && npx some-pkg` is examined on its own.
var shellSegmentRe = regexp.MustCompile(`&&|\|\||[|;&\n]`)

// hookNpmPackageSpecs extracts the package spec of every npm-runner invocation
// (npx/bunx/pnpm dlx/yarn dlx) found in a hook command string. Path-like args
// (./x, ../x, /x) are dropped — those run a local script, not a fetched package.
func hookNpmPackageSpecs(command string) []string {
	var specs []string
	for _, seg := range shellSegmentRe.Split(command, -1) {
		fields := strings.Fields(seg)
		if len(fields) == 0 {
			continue
		}
		runner := filepath.Base(fields[0])
		if !npmPackageRunners[runner] {
			continue
		}
		if spec := hookRunnerPackage(runner, fields[1:]); spec != "" && !isPathLikeArg(spec) {
			specs = append(specs, spec)
		}
	}
	return specs
}

// hookRunnerPackage returns the package spec a runner fetches and executes, or "".
// Unlike mcpPackageArg it is strict about pnpm/yarn: only the `dlx`/`exec` form
// runs a remote package, so bare `pnpm install` / `yarn build` (whose first token
// is a subcommand, not a package) yields "" and is never treated as a package.
func hookRunnerPackage(runner string, args []string) string {
	if runner == "pnpm" || runner == "yarn" {
		for i, a := range args {
			if a != "dlx" && a != "exec" {
				continue
			}
			for _, b := range args[i+1:] {
				if strings.HasPrefix(b, "-") {
					continue
				}
				return b
			}
		}
		return ""
	}
	for _, a := range args { // npx / bunx: first non-flag arg is the package
		if strings.HasPrefix(a, "-") {
			continue
		}
		return a
	}
	return ""
}

// squatMatch is a detected similarity to a known-good identifier.
type squatMatch struct {
	official string
	severity finding.Severity
	reason   string
}

// bestSquat reports the strongest typosquat signal between value and any entry
// in allow, or nil. An exact (case-folded) match to any entry means value is
// legitimate and is never reported.
func bestSquat(value string, allow []string) *squatMatch {
	vlow := strings.ToLower(strings.TrimSpace(value))
	if vlow == "" {
		return nil
	}
	for _, e := range allow {
		if vlow == strings.ToLower(e) {
			return nil // exact known-good
		}
	}
	vfold := homoglyphFold(vlow)
	for _, e := range allow {
		if homoglyphFold(strings.ToLower(e)) == vfold {
			return &squatMatch{e, finding.Error, "homoglyph substitution"}
		}
	}
	var best *squatMatch
	for _, e := range allow {
		elow := strings.ToLower(e)
		if len([]rune(elow)) < 8 { // short names make edit-distance noisy
			continue
		}
		switch levenshtein(vlow, elow) {
		case 1:
			return &squatMatch{e, finding.Error, "one-character difference"}
		case 2:
			if best == nil {
				best = &squatMatch{e, finding.Warn, "within two characters"}
			}
		}
	}
	return best
}

// bestPackageSquat compares an npm package spec (version stripped) against the
// known packages, and additionally flags an official server name carried under a
// non-official scope (e.g. @evil/server-filesystem).
func bestPackageSquat(spec string) *squatMatch {
	name := npmPackageName(spec)
	if m := bestSquat(name, knownMCPPackages); m != nil {
		return m
	}
	u := homoglyphFold(strings.ToLower(npmUnscoped(name)))
	if len([]rune(u)) < 8 {
		return nil
	}
	for _, e := range knownMCPPackages {
		if homoglyphFold(strings.ToLower(npmUnscoped(e))) == u && !strings.EqualFold(name, e) {
			return &squatMatch{e, finding.Warn, "official MCP server name under a non-official scope"}
		}
	}
	return nil
}

// npmPackageName strips a trailing @version from a package spec, keeping any
// @scope prefix: "@scope/name@1.2.3" → "@scope/name", "name@1" → "name".
func npmPackageName(spec string) string {
	if strings.HasPrefix(spec, "@") {
		slash := strings.IndexByte(spec, '/')
		if slash < 0 {
			return spec
		}
		if at := strings.IndexByte(spec[slash:], '@'); at >= 0 {
			return spec[:slash+at]
		}
		return spec
	}
	if at := strings.IndexByte(spec, '@'); at >= 0 {
		return spec[:at]
	}
	return spec
}

// npmUnscoped drops a leading @scope/, returning the bare package name.
func npmUnscoped(pkg string) string {
	if strings.HasPrefix(pkg, "@") {
		if i := strings.IndexByte(pkg, '/'); i >= 0 {
			return pkg[i+1:]
		}
	}
	return pkg
}

// homoglyphRunes maps the digits most commonly substituted for letters in
// typosquats to their letter form. Applied after lower-casing.
var homoglyphRunes = map[rune]rune{
	'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't',
}

func homoglyphFold(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if h, ok := homoglyphRunes[r]; ok {
			b.WriteRune(h)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// levenshtein returns the edit distance between a and b (rune-based).
func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	la, lb := len(ra), len(rb)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		cur := make([]int, lb+1)
		cur[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[lb]
}
