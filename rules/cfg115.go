// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg115 struct{}

var CFG115 = &cfg115{}

func init() { All = append(All, CFG115) }

func (r *cfg115) ID() string { return "CFG115" }

// sensitiveLinkTargetRe matches a link target where a write through the link
// gives an attacker code execution or access: SSH and cloud credentials, shell
// start-up files, agent and package-manager configuration, Git configuration
// and hooks, persistence folders, and executable search paths. It is matched
// on link metadata only, after normalising both separator styles to slashes.
var sensitiveLinkTargetRe = regexp.MustCompile(`(?i)(?:^|/)(?:` +
	`\.ssh|\.aws|\.gnupg|` +
	`\.npmrc|` +
	`\.bashrc|\.bash_profile|\.bash_login|\.zshrc|\.zprofile|\.profile|` +
	`\.claude|\.codex|\.gemini|\.cursor|` +
	`\.config/(?:claude|codex|gemini|cursor|git)|` +
	`\.gitconfig|\.git/(?:config|hooks)|` +
	`crontab|cron\.d|spool/cron|LaunchAgents|LaunchDaemons|` +
	`\.local/bin|windows/system32|windowsapps` +
	`)(?:/|$)`)

var executableLinkTargetRe = regexp.MustCompile(`(?i)^(?:` +
	`/(?:s?bin|usr/(?:local/)?s?bin)|` +
	`(?:~|\$home|\$\{home\}|%userprofile%)/bin` +
	`)(?:/|$)`)

func normalizedLinkTarget(target string) string {
	return strings.ReplaceAll(filepath.ToSlash(target), `\`, "/")
}

func sensitiveLinkTarget(target string) bool {
	normalized := normalizedLinkTarget(target)
	return sensitiveLinkTargetRe.MatchString(normalized) || executableLinkTargetRe.MatchString(normalized)
}

// Check reports a path in the scanned repository that is, or passes through, a
// symbolic link resolving outside the repository.
//
// The operating system follows the link for every reader. An agent that loads
// .claude/settings.json, .mcp.json or CLAUDE.md through such a link loads a
// file from the machine that checked the repository out, not from the
// repository, so what the repository appears to declare and what the agent
// reads differ. cfgaudit used to follow the link too, reading and quoting a
// file outside the directory it was asked to scan (GHSA-x9h6-c6v9-v699). It no
// longer opens the target; this rule makes the skipped file visible instead of
// letting it pass as absent.
//
// The repository walk adds any other committed link that leaves the repository
// (#1417): an agent that writes to such a file as part of the project writes
// through the link to the target (CVE-2025-55345, CVE-2026-12958).
//
// Warn: the link's content is unknown by design, so nothing is claimed about
// what it configures, only that the repository hands the choice to whatever
// exists at that path on the reader's machine. Error when the text names a
// sensitive location, because then the repository says what it is after.
func (r *cfg115) Check(t *Target) []finding.Finding {
	if t == nil || t.EscapedLink == "" {
		return nil
	}
	link := t.EscapedTarget
	if link == "" {
		link = "a path outside the repository"
	} else {
		link = "\"" + normalizedLinkTarget(link) + "\""
	}
	severity, sensitive := finding.Warn, ""
	if sensitiveLinkTarget(t.EscapedTarget) {
		severity, sensitive = finding.Error, " That is a sensitive location: a write through the link gives access or runs code on the developer's machine."
	}
	message := "this path is a symbolic link to " + link + ", outside the scanned repository. An agent that opens it loads a file from the machine that checked the repository out, not from the repository." +
		sensitive + " cfgaudit did not read it and no other rule ran on it. Commit the file itself instead of a link"
	if t.EscapedWalked {
		message = "this committed symbolic link points to " + link + ", outside the repository. An agent that writes to it as a project file writes to that path on the developer's machine." +
			sensitive + " Commit a regular file, or keep the link inside the repository"
	}
	return []finding.Finding{{
		RuleID:   "CFG115",
		Severity: severity,
		Scope:    t.Scope,
		File:     t.EscapedLink,
		Message:  message,
	}}
}
