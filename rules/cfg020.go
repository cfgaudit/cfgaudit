package rules

import (
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg020 struct{}

var CFG020 = &cfg020{}

func init() { All = append(All, CFG020) }

func (r *cfg020) ID() string { return "CFG020" }

// dynamicLinkerInjectionVars are env keys that make the dynamic linker load an
// attacker-controlled shared library into the process before any of its own code
// runs — granting full control (intercept syscalls, read memory, exfiltrate)
// while the server appears to work normally. Covers the Linux (LD_*) and macOS
// (DYLD_*) loaders.
var dynamicLinkerInjectionVars = map[string]bool{
	"LD_PRELOAD":            true,
	"LD_LIBRARY_PATH":       true,
	"LD_AUDIT":              true,
	"DYLD_INSERT_LIBRARIES": true,
	"DYLD_LIBRARY_PATH":     true,
}

// Check flags MCP servers whose env injects a shared library via the dynamic
// linker. Covers both settings.json mcpServers and the project .mcp.json.
func (r *cfg020) Check(t *Target) []finding.Finding {
	var findings []finding.Finding
	for _, ref := range t.mcpServerRefs() {
		for _, key := range injectionVarsInEnv(ref.Server.Env) {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG020",
				Severity: finding.Error,
				File:     ref.File,
				Message: "mcpServers." + ref.Name + ".env sets " + key +
					" — the dynamic linker loads this shared library into the server process before its own code runs, granting full control over it; remove it",
			})
		}
	}
	return findings
}

// injectionVarsInEnv returns the dynamic-linker injection keys present in env,
// sorted for deterministic output.
func injectionVarsInEnv(env map[string]string) []string {
	var keys []string
	for k := range env {
		if dynamicLinkerInjectionVars[strings.ToUpper(k)] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}
