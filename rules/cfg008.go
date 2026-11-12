// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strings"

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
				Line:     site.Line,
				Message:  site.Label + " matches reverse-shell pattern (" + label + ") — grants remote interactive access when it runs" + userScopeNote(t),
			})
		}
	}
	return findings
}

// Compiled once; devTcpReverseShell is called per command site.
var (
	devTcpInteractiveRe   = regexp.MustCompile(`\b(?:bash|sh|zsh)(?:\.exe)?\s+-i\b`)
	devTcpShellRedirectRe = regexp.MustCompile(`\b(?:bash|sh|zsh)(?:\.exe)?\b\s+>&\s*/dev/tcp/`)
	devTcpExecFdRe        = regexp.MustCompile(`exec\s+(\d+)<>`)
	devTcpShellFdRe       = regexp.MustCompile(`\b(?:bash|sh|zsh)(?:\.exe)?\b\s+(?:0<&(\d+)|<&(\d+)|>&(\d+)|\d+<&(\d+))`)
	devTcpCatFdRe         = regexp.MustCompile(`cat\s+<&(\d+)\s*\|\s*\b(?:bash|sh|zsh)(?:\.exe)?\b`)
)

// devTcpReverseShell reports whether a command uses /dev/tcp/ as a reverse
// shell rather than a plain connectivity probe. A bare exec N<>/dev/tcp/...,
// a parenthesised probe, a printf ... >&N write to the socket, or a
// </dev/tcp/... port check does not count; the socket must be wired to a
// shell's stdio.
func devTcpReverseShell(cmd string) bool {
	if !strings.Contains(cmd, "/dev/tcp/") {
		return false
	}

	// Interactive shell redirected to or from the socket.
	if devTcpInteractiveRe.MatchString(cmd) {
		return true
	}
	// A shell whose stdin/stdout is the socket via 0>&1.
	if strings.Contains(cmd, "0>&1") {
		return true
	}
	// A shell redirecting its stdout straight to the socket.
	if devTcpShellRedirectRe.MatchString(cmd) {
		return true
	}

	// exec N<>/dev/tcp/... followed by a shell that reads from or writes to
	// that file descriptor.
	execFds := make(map[string]bool)
	for _, m := range devTcpExecFdRe.FindAllStringSubmatch(cmd, -1) {
		execFds[m[1]] = true
	}
	if len(execFds) > 0 {
		for _, m := range devTcpShellFdRe.FindAllStringSubmatch(cmd, -1) {
			for i := 1; i < len(m); i++ {
				if m[i] != "" && execFds[m[i]] {
					return true
				}
			}
		}
		for _, m := range devTcpCatFdRe.FindAllStringSubmatch(cmd, -1) {
			if execFds[m[1]] {
				return true
			}
		}
	}

	return false
}

func matchReverseShell(cmd string) (string, bool) {
	if devTcpReverseShell(cmd) {
		return "/dev/tcp/ redirect (bash networking)", true
	}
	for _, p := range reverseShellPatterns {
		if p.re.MatchString(cmd) {
			return p.label, true
		}
	}
	return "", false
}
