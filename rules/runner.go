package rules

import (
	"fmt"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/version"
)

// Versioned is implemented by rules that require a minimum Claude Code release.
// MinVersion returns a SemVer-like string ("2.1.91"); an empty string means
// the rule applies to every version.
type Versioned interface {
	MinVersion() string
}

// Run executes every registered rule against target.
//
// If detected is non-nil, rules implementing Versioned with a MinVersion
// above detected are skipped and replaced by a single info-severity finding
// so the omission is visible in the output. A nil detected disables all
// version gating — every rule runs unconditionally.
//
// If accept is non-nil it is consulted before each rule; rules for which
// accept returns false are dropped silently (the caller, e.g. a CLI flag,
// is expected to print its own "rule excluded" feedback if relevant).
//
// Every finding has its Scope back-filled from target.Scope when the rule
// did not set one itself, so JSON consumers can filter by blast radius
// without each rule having to remember to populate the field.
func Run(target *Target, detected *version.Version, accept func(Rule) bool) []finding.Finding {
	// Expose the detected version to rules whose findings depend on version-gated
	// runtime semantics (e.g. the deny-all "*" glob handling in CFG041–044).
	target.ClaudeVersion = detected

	var out []finding.Finding
	for _, r := range All {
		if accept != nil && !accept(r) {
			continue
		}
		if detected != nil {
			if skipMsg := versionSkip(r, *detected); skipMsg != "" {
				out = append(out, finding.Finding{
					RuleID:   r.ID(),
					Severity: finding.Info,
					Scope:    target.Scope,
					File:     target.SettingsFile,
					Message:  skipMsg,
				})
				continue
			}
		}
		results := r.Check(target)
		for i := range results {
			if results[i].Scope == "" {
				results[i].Scope = target.Scope
			}
		}
		out = append(out, results...)
	}
	return out
}

// versionSkip returns a non-empty notice message when r is Versioned and
// requires a Claude Code release newer than detected.
func versionSkip(r Rule, detected version.Version) string {
	v, ok := r.(Versioned)
	if !ok {
		return ""
	}
	minStr := v.MinVersion()
	if minStr == "" {
		return ""
	}
	min, err := version.Parse(minStr)
	if err != nil {
		return ""
	}
	if detected.AtLeast(min) {
		return ""
	}
	return fmt.Sprintf("skipped: requires Claude Code >= %s, detected %s", minStr, detected)
}
