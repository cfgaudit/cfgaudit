// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg008 struct{}

var CFG008 = &cfg008{}

func init() { All = append(All, CFG008) }

func (r *cfg008) ID() string { return "CFG008" }

// reverseShellPatterns match command strings that establish or stage a reverse shell.
// Patterns are tight enough to avoid common false matches but ordered by specificity.
var reverseShellPatterns = []struct {
	re    *regexp.Regexp
	label string
}{
	{regexp.MustCompile(`/dev/tcp/`), "/dev/tcp/ redirect (bash networking)"},
	// netcat in command position: not after "-", so `jq -nc` is not netcat
	// (#1356), and the -e/-l flag is an argument of its own.
	{regexp.MustCompile(`(?:^|[\s;&|(` + "`" + `"'])(?:nc|ncat|netcat)\s+(?:[^|;&\n]*\s)?-[A-Za-z]*[el][A-Za-z]*\b`), "netcat with -e/-l flag"},
	{regexp.MustCompile(`\bbash\s+-i\b[^|;&\n]{0,40}[>&]`), "interactive bash redirected"},
	{regexp.MustCompile(`\bmkfifo\s+/tmp/`), "mkfifo staging in /tmp"},
	{regexp.MustCompile(`\bsocat\b[^|;&\n]{0,80}\bexec\b`), "socat exec bridge"},
	{regexp.MustCompile(`(?i)New-Object\s+(?:System\.)?Net\.Sockets\.TCPClient`), "PowerShell TCPClient reverse shell"},
	// Only after powershell or pwsh on the same line: `plutil -extract
	// CFBundleShortVersionString` is not an encoded command (#1356).
	{regexp.MustCompile(`(?i)\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]*?(?:^|[\s"'` + "`" + `(])-e[a-z]*\s+[A-Za-z0-9+/=]{24,}`), "PowerShell encoded command (-EncodedCommand)"},
}

func (r *cfg008) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}

	var findings []finding.Finding
	for _, site := range commandSitesWithScripts(t) {
		if label, ok := matchReverseShell(site.Command); ok {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG008",
				Severity: finding.Error,
				File:     site.File,
				Message:  site.Label + " matches reverse-shell pattern (" + label + ") — grants remote interactive access when it runs" + userScopeNote(t),
			})
		}
	}
	return findings
}

func matchReverseShell(cmd string) (string, bool) {
	for _, p := range reverseShellPatterns {
		if p.re.MatchString(cmd) {
			return p.label, true
		}
	}
	return "", false
}
