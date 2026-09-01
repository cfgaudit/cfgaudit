package rules

import (
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg107 struct{}

// CFG107 reports a committed Codex config whose shell_environment_policy.set
// injects code into every shell Codex spawns.
var CFG107 = &cfg107{}

func init() { All = append(All, CFG107) }

func (r *cfg107) ID() string { return "CFG107" }

// searchPathEnvVars are the two variables in codeExecEnvVars that widen where a
// loader *looks* for libraries rather than force-loading one. On an MCP server's
// env (CFG020) any value is worth reporting, because a server declaration has no
// reason to carry one. This table exists to prepare the environment of build and
// test shells, where an absolute system path is ordinary: two of the 73 real
// configs measured for this rule set LD_LIBRARY_PATH to a CUDA path and nothing
// else in the sample came close.
//
// So on this surface the two are value-gated on the property that makes them
// dangerous: a relative entry resolves against the process working directory,
// which for a spawned shell is the repository, so the repository chooses the
// directory the loader searches first. An empty entry means the same thing.
var searchPathEnvVars = map[string]bool{
	"LD_LIBRARY_PATH":   true,
	"DYLD_LIBRARY_PATH": true,
}

// hasRelativeEntry reports whether any entry of a search path is relative,
// including the empty entry that stands for the working directory.
//
// Colon-separated and slash-rooted without a Windows branch, deliberately. Both
// variables this is applied to are the Unix and macOS dynamic loader's, and
// neither exists on Windows, so a drive letter here would not be a path to
// classify but a value that cannot occur. Splitting on ":" to accommodate one
// would also break the very separator the variables use.
func hasRelativeEntry(v string) bool {
	for _, entry := range strings.Split(v, ":") {
		e := strings.TrimSpace(entry)
		if e == "" {
			return true
		}
		if !strings.HasPrefix(e, "/") {
			return true
		}
	}
	return false
}

// Check reports interpreter and dynamic-linker startup variables set in
// [shell_environment_policy] set. Upstream describes the table as the "Policy
// for building the `env` when spawning a process via shell-like tools", so a
// value here reaches every shell the agent runs, not one server process.
//
// The classifier is CFG020's codeExecEnvVars, deliberately: this is the same
// attack on a different surface, and one list means one place to maintain the
// mechanism text. What differs is the gate on the two search-path variables,
// explained at searchPathEnvVars.
//
// Upstream treats two of these keys as dangerous in exactly this position. The
// project-config sanitizer removes ZDOTDIR and BASH_ENV from
// shell_environment_policy.set, and only when the credential broker is enabled,
// which is an optional feature that is off unless a trusted layer turns it on.
func (r *cfg107) Check(t *Target) []finding.Finding {
	if t == nil || t.Codex == nil || t.Codex.ShellEnvironmentPolicy == nil {
		return nil
	}
	set := t.Codex.ShellEnvironmentPolicy.Set
	if len(set) == 0 {
		return nil
	}

	var keys []string
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var findings []finding.Finding
	for _, key := range keys {
		upper := strings.ToUpper(key)
		spec, ok := codeExecEnvVars[upper]
		if !ok {
			continue
		}
		value := set[key]
		if strings.TrimSpace(value) == "" {
			continue
		}
		if spec.valueRe != nil && !spec.valueRe.MatchString(value) {
			continue
		}
		if searchPathEnvVars[upper] && !hasRelativeEntry(value) {
			continue
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG107",
			Severity: finding.Error,
			Scope:    t.Scope,
			File:     t.CodexFile,
			Message: "shell_environment_policy.set sets " + key + " — " + spec.mechanism +
				", and this table is applied to every shell Codex spawns, so the value runs attacker-controlled code on the next command; remove it" +
				userScopeNote(t),
		})
	}
	return findings
}
