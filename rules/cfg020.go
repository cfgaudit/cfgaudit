package rules

import (
	"regexp"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg020 struct{}

var CFG020 = &cfg020{}

func init() { All = append(All, CFG020) }

func (r *cfg020) ID() string { return "CFG020" }

// envCodeExecVar describes an env var that runs attacker-controlled code when set
// on an MCP server process. A presence var (valueRe nil) is dangerous with any
// non-empty value; a value-gated var only when the value carries a code-loading
// flag — these have legitimate non-code uses (NODE_OPTIONS=--max-old-space-size,
// RUBYOPT=-W0) so blindly flagging them would false-positive.
type envCodeExecVar struct {
	valueRe   *regexp.Regexp
	mechanism string
}

const linkerMechanism = "the dynamic linker loads this shared library into the server process before its own code runs"

var (
	// Node loads a module at startup via --require/--import/-r (but not benign
	// flags like --max-old-space-size); Ruby via -r; Perl via -M/-m.
	nodeRequireRe = regexp.MustCompile(`(?i)(^|\s)(--require|--import|-r)(\s|=|$)`)
	rubyRequireRe = regexp.MustCompile(`(?i)(^|\s)-r`)
	perlModuleRe  = regexp.MustCompile(`(?i)(^|\s)-[Mm]`)

	// codeExecEnvVars maps an upper-cased env key to how it injects code. Covers
	// dynamic-linker injection (LD_*/DYLD_*) and the interpreter startup vectors
	// of CVE-2026-44995 (NODE_OPTIONS/BASH_ENV/RUBYOPT/PYTHONSTARTUP/PERL5OPT).
	codeExecEnvVars = map[string]envCodeExecVar{
		"LD_PRELOAD":            {mechanism: linkerMechanism},
		"LD_LIBRARY_PATH":       {mechanism: linkerMechanism},
		"LD_AUDIT":              {mechanism: linkerMechanism},
		"DYLD_INSERT_LIBRARIES": {mechanism: linkerMechanism},
		"DYLD_LIBRARY_PATH":     {mechanism: linkerMechanism},
		"BASH_ENV":              {mechanism: "bash sources this file as its non-interactive startup script"},
		"PYTHONSTARTUP":         {mechanism: "Python executes this script at interpreter startup"},
		"NODE_OPTIONS":          {valueRe: nodeRequireRe, mechanism: "Node.js loads a module at startup via --require/--import"},
		"RUBYOPT":               {valueRe: rubyRequireRe, mechanism: "Ruby requires a module at interpreter startup via -r"},
		"PERL5OPT":              {valueRe: perlModuleRe, mechanism: "Perl loads a module at startup via -M/-m"},
	}
)

// Check flags MCP servers whose env injects code into the server process at
// startup — a dynamic-linker shared library, or an interpreter startup
// file/flag (CVE-2026-44995). Covers both settings.json mcpServers and the
// project .mcp.json.
func (r *cfg020) Check(t *Target) []finding.Finding {
	var findings []finding.Finding
	for _, ref := range t.mcpServerRefs() {
		for _, key := range codeExecEnvKeys(ref.Server.Env) {
			spec := codeExecEnvVars[strings.ToUpper(key)]
			findings = append(findings, finding.Finding{
				RuleID:   "CFG020",
				Severity: finding.Error,
				File:     ref.File,
				Message: "mcpServers." + ref.Name + ".env sets " + key + " — " + spec.mechanism +
					", running attacker-controlled code when the server process starts; remove it",
			})
		}
	}
	return findings
}

// codeExecEnvKeys returns the code-execution env keys present (and, for
// value-gated vars, matching) in env, sorted for deterministic output.
func codeExecEnvKeys(env map[string]string) []string {
	var keys []string
	for k, v := range env {
		spec, ok := codeExecEnvVars[strings.ToUpper(k)]
		if !ok {
			continue
		}
		if strings.TrimSpace(v) == "" {
			continue
		}
		if spec.valueRe != nil && !spec.valueRe.MatchString(v) {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
