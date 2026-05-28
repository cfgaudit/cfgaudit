package rules

import (
	"regexp"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg039 struct{}

var CFG039 = &cfg039{}

func init() { All = append(All, CFG039) }

func (r *cfg039) ID() string { return "CFG039" }

var (
	// rmArgsRe captures the argument run of an `rm` invocation (up to a separator).
	rmArgsRe = regexp.MustCompile(`(?i)\brm\b([^|;&\n]*)`)
	// recursiveFlagRe / forceFlagRe detect -r/-R/--recursive and -f/--force in
	// either combined (-rf) or separate (-r -f) form.
	recursiveFlagRe = regexp.MustCompile(`(?i)(?:^|\s)-[a-z]*r|--recursive\b`)
	forceFlagRe     = regexp.MustCompile(`(?i)(?:^|\s)-[a-z]*f|--force\b`)
	// broadTargetRe matches a clearly catastrophic delete target: ~ , / , .. ,
	// $HOME, *, or a /* glob — as the whole target, not a scoped sub-path.
	broadTargetRe = regexp.MustCompile(`(?i)(?:\s~(?:\s|$)|\s/(?:\s|$)|\s\.\.(?:/?\s|$)|\$\{?HOME\}?|/\*(?:\s|$)|\s\*(?:\s|$))`)
)

// Check flags command sites that run a recursive force-delete (rm -rf). In a
// hook this fires automatically on every matched event, so a single bad entry
// can wipe a directory with no confirmation. warn normally; error when the
// target is clearly broad (~, /, .., $HOME, *). Covers hooks and helpers.
func (r *cfg039) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	for _, site := range commandSites(t) {
		sev, ok := rmForceDeleteSeverity(site.Command)
		if !ok {
			continue
		}
		msg := site.Label + " runs a recursive force-delete (rm -rf) — in a hook this executes automatically with no confirmation; scope it to a specific path"
		if sev == finding.Error {
			msg = site.Label + " runs a recursive force-delete (rm -rf) against a broad target (e.g. ~, /, .., $HOME, *) — this can wipe the project or home directory; remove it"
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG039",
			Severity: sev,
			File:     site.File,
			Message:  msg + userScopeNote(t),
		})
	}
	return findings
}

// rmForceDeleteSeverity returns (severity, true) when cmd contains an rm
// invocation with both recursive and force flags. Severity is error for a broad
// target, else warn.
func rmForceDeleteSeverity(cmd string) (finding.Severity, bool) {
	found := false
	broad := false
	for _, m := range rmArgsRe.FindAllStringSubmatch(cmd, -1) {
		args := m[1]
		if !recursiveFlagRe.MatchString(args) || !forceFlagRe.MatchString(args) {
			continue
		}
		found = true
		if broadTargetRe.MatchString(args) {
			broad = true
		}
	}
	if !found {
		return "", false
	}
	if broad {
		return finding.Error, true
	}
	return finding.Warn, true
}
