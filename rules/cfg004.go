package rules

import (
	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/version"
)

type cfg004 struct{}

var CFG004 = &cfg004{}

func init() { All = append(All, CFG004) }

func (r *cfg004) ID() string { return "CFG004" }

// No MinVersion: this rule is presence-based — it fires only when defaultMode is
// set to bypassPermissions/auto. The version dependence below is of the opposite
// kind and cannot be expressed as a lower bound: the key is neither renamed nor
// removed, what changed is whether a repo-controllable file may grant the mode,
// and only the detected version separates the two worlds. CFG004 is Claude-only
// (t.Settings comes from the three Claude settings files), so a Claude version
// gate here does not touch another agent's findings.
//
// Both cutoffs are measured against the shipped binaries rather than read off the
// CHANGELOG, on one repository carrying the value in .claude/settings.json:
//
//	2.1.252  auto   → [WARN] "…defaultMode \"auto\" ignored…", session mode=default
//	2.1.252  bypass → no warning, session mode=bypassPermissions
//	2.1.263  bypass → [WARN] "…only policy/user/flag settings may grant bypass
//	                  mode (projectSettings and localSettings are repo-controllable)",
//	                  session mode=default
//	2.1.263  user-scope bypass → no warning, session mode=bypassPermissions
//
// So "auto" was already ignored in the oldest binary available, and 2.1.252 is an
// upper bound on its real cutoff rather than the cutoff itself; treating it as the
// cutoff errs towards reporting, which is the safe direction. The bypass half is
// bracketed exactly, and 2.1.257 is also the release the CHANGELOG names.
var (
	autoIgnoredFromScope   = version.Version{Major: 2, Minor: 1, Patch: 252}
	bypassIgnoredFromScope = version.Version{Major: 2, Minor: 1, Patch: 257}
)

// Check reads permissions.defaultMode — the schema-correct nested location. A
// top-level `defaultMode` is not the schema key and is not honoured by Claude
// Code, so matching it would be a false positive; it is deliberately NOT matched.
func (r *cfg004) Check(t *Target) []finding.Finding {
	if t.Settings == nil || t.Settings.Permissions == nil {
		return nil
	}
	switch t.Settings.Permissions.DefaultMode {
	case "bypassPermissions":
		if inert, detected := modeIgnoredHere(t, bypassIgnoredFromScope); inert {
			return []finding.Finding{r.report(t, finding.Warn,
				"defaultMode: \"bypassPermissions\" in a repository-controlled settings file is ignored by the detected Claude Code "+detected+
					": since 2.1.257 only policy, user or flag settings may grant bypass mode. It is not harmless, because it is still honoured by anyone who clones this repository on an older release, and there it disables every permission check. Remove the key from the committed file")}
		}
		return []finding.Finding{r.report(t, finding.Error,
			"defaultMode: \"bypassPermissions\" disables all permission checks — Claude Code runs with full autonomy and no confirmation prompts"+userScopeNote(t))}
	case "auto":
		if inert, detected := modeIgnoredHere(t, autoIgnoredFromScope); inert {
			return []finding.Finding{r.report(t, finding.Info,
				"defaultMode: \"auto\" in a repository-controlled settings file is ignored by the detected Claude Code "+detected+
					": only policy, user or flag settings may grant auto mode. Anyone who clones this repository on an older release still gets confirmation prompts suppressed, so remove the key rather than relying on their version")}
		}
		return []finding.Finding{r.report(t, finding.Warn,
			"defaultMode: \"auto\" suppresses all confirmation prompts — review allow/deny rules carefully before enabling"+userScopeNote(t))}
	}
	return nil
}

func (r *cfg004) report(t *Target, sev finding.Severity, msg string) finding.Finding {
	return finding.Finding{
		RuleID:   "CFG004",
		Severity: sev,
		Scope:    t.Scope,
		File:     t.SettingsFile,
		Message:  msg,
	}
}

// modeIgnoredHere reports whether the detected Claude Code discards this file's
// defaultMode, which is true only for the two repo-controllable scopes and only
// from the release that stopped honouring the value.
//
// An undetected version keeps the honoured reading. cfgaudit audits a file other
// people's installations will read, so the absence of version information must
// not be taken as "the newest behaviour applies"; that would hide a value which
// is live for every reader on an older release.
func modeIgnoredHere(t *Target, from version.Version) (bool, string) {
	if t.Scope != finding.ScopeProject && t.Scope != finding.ScopeProjectLocal {
		return false, ""
	}
	if t.ClaudeVersion == nil || !t.ClaudeVersion.AtLeast(from) {
		return false, ""
	}
	return true, t.ClaudeVersion.String()
}
