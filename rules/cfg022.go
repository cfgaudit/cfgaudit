package rules

import (
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg022 struct{}

var CFG022 = &cfg022{}

func init() { All = append(All, CFG022) }

func (r *cfg022) ID() string { return "CFG022" }

// Check flags sandbox settings that weaken or hijack Claude Code's execution
// sandbox:
//
//   - bwrapPath / socatPath are honored only from managed settings; their presence
//     in any file cfgaudit scans (project, project-local, user) is an attempt to
//     point the sandbox's bubblewrap binary or network proxy at an attacker path.
//   - excludedCommands lists commands that run outside the sandbox. Excluding "*"
//     or a shell interpreter hands arbitrary code execution outside the sandbox
//     (error); other exclusions are surfaced for review (warn).
//   - allowAppleEvents (macOS) lets sandboxed commands launch other apps
//     unsandboxed and drive them via AppleScript, removing code-execution
//     isolation. It is honored only from user/managed/CLI settings — project
//     settings cannot enable it — so this fires only for user-scope targets
//     (the inverse of bwrapPath/socatPath, which are anomalous in any scanned
//     file); in a project settings file the key is inert and not flagged (warn).
func (r *cfg022) Check(t *Target) []finding.Finding {
	if t == nil || t.Settings == nil {
		return nil
	}
	sb := t.Settings.Sandbox()
	if sb == nil {
		return nil
	}

	var findings []finding.Finding
	add := func(sev finding.Severity, msg string) {
		findings = append(findings, finding.Finding{
			RuleID:   "CFG022",
			Severity: sev,
			File:     t.SettingsFile,
			Message:  msg + userScopeNote(t),
		})
	}

	if sb.BwrapPath != "" {
		add(finding.Error, "sandbox.bwrapPath is set to \""+sb.BwrapPath+"\" — this key is honored only from admin-managed settings; in a project/user settings file it repoints the sandbox's bubblewrap binary at an attacker-controlled path")
	}
	if sb.SocatPath != "" {
		add(finding.Error, "sandbox.socatPath is set to \""+sb.SocatPath+"\" — this key is honored only from admin-managed settings; in a project/user settings file it repoints the sandbox's network proxy (socat) at an attacker-controlled binary")
	}

	var broad, other []string
	for _, c := range sb.ExcludedCommands {
		if isBroadExclusion(c) {
			broad = append(broad, c)
		} else if strings.TrimSpace(c) != "" {
			other = append(other, c)
		}
	}
	if len(broad) > 0 {
		add(finding.Error, "sandbox.excludedCommands runs "+strings.Join(quotedList(broad), ", ")+
			" outside the sandbox — excluding a wildcard or a shell interpreter effectively disables sandboxing for arbitrary commands")
	}
	if len(other) > 0 {
		add(finding.Warn, "sandbox.excludedCommands runs "+strings.Join(quotedList(other), ", ")+
			" outside the sandbox — confirm each command genuinely needs to bypass the sandbox")
	}

	// allowAppleEvents is honored only from user/managed/CLI settings; Claude Code
	// ignores it in project/project-local settings. Flag it only where it takes
	// effect (user scope) so a committed .claude/settings.json carrying an inert
	// copy does not produce a false positive.
	if sb.AllowAppleEvents && t.Scope == finding.ScopeUser {
		add(finding.Warn, "sandbox.allowAppleEvents is true — sandboxed commands can launch other applications unsandboxed with no prompt and drive them via AppleScript, removing the sandbox's code-execution isolation (the macOS automation-consent prompt (TCC) still gates each target). Scope the specific tool with excludedCommands instead of this blanket opt-in")
	}
	return findings
}

// isBroadExclusion reports whether an excludedCommands entry hands arbitrary code
// execution outside the sandbox: the catch-all "*", or a shell interpreter
// (optionally with arguments, e.g. "bash", "bash *", "/bin/sh -c …").
func isBroadExclusion(entry string) bool {
	e := strings.TrimSpace(entry)
	if e == "*" {
		return true
	}
	fields := strings.Fields(e)
	if len(fields) == 0 {
		return false
	}
	return shellInterpreterName(fields[0]) != ""
}
