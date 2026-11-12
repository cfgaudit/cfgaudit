// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
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

// devTcpReverseShell reports whether a command uses /dev/tcp/ as a reverse
// shell rather than a plain connectivity probe. A bare exec N<>/dev/tcp/...
// probe, a parenthesised probe, or a printf ... >&N write to the socket does
// not count; the socket must be wired to a shell's stdio.
func devTcpReverseShell(cmd string) bool {
	if !strings.Contains(cmd, "/dev/tcp/") {
		return false
	}

	// Interactive shell redirected to or from the socket.
	if regexp.MustCompile(`\b(?:bash|sh|zsh)(?:\.exe)?\s+-i\b`).MatchString(cmd) {
		return true
	}
	// A shell whose stdin/stdout is the socket.
	if strings.Contains(cmd, "0>&1") {
		return true
	}
	if regexp.MustCompile(`>&\s*/dev/tcp/`).MatchString(cmd) {
		return true
	}
	// Reading from the socket into a command (cat < /dev/tcp/...).
	if regexp.MustCompile(`<\s*/dev/tcp/`).MatchString(cmd) {
		return true
	}

	// exec N<>/dev/tcp/... followed by a shell that reads from or writes to
	// that file descriptor.
	for _, m := range regexp.MustCompile(`exec\s+(\d+)<>`).FindAllStringSubmatch(cmd, -1) {
		fd := m[1]
		patterns := []string{
			fmt.Sprintf(`\b(?:bash|sh|zsh)(?:\.exe)?\s+(?:0<&%s|<&%s|>&%s|\d+<&%s)`, fd, fd, fd, fd),
			fmt.Sprintf(`cat\s+<&%s\s*\|`, fd),
			fmt.Sprintf(`while\s+read[^;\n]*<\&%s`, fd),
		}
		for _, p := range patterns {
			if regexp.MustCompile(p).MatchString(cmd) {
				return true
			}
		}
	}

	// Generic forms that pipe a socket fd into a shell.
	if regexp.MustCompile(`cat\s+<&\d+\s*\|\s*(?:bash|sh|zsh)`).MatchString(cmd) {
		return true
	}
	if regexp.MustCompile(`while\s+read[^;\n]*<\&\d+`).MatchString(cmd) {
		return true
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
