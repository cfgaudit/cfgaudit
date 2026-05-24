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
	{regexp.MustCompile(`\b(?:nc|ncat)\s+[^|;&\n]*-[A-Za-z]*[el]`), "netcat with -e/-l flag"},
	{regexp.MustCompile(`\bbash\s+-i\b[^|;&\n]{0,40}[>&]`), "interactive bash redirected"},
	{regexp.MustCompile(`\bmkfifo\s+/tmp/`), "mkfifo staging in /tmp"},
	{regexp.MustCompile(`\bsocat\b[^|;&\n]{0,80}\bexec\b`), "socat exec bridge"},
	{regexp.MustCompile(`(?i)New-Object\s+(?:System\.)?Net\.Sockets\.TCPClient`), "PowerShell TCPClient reverse shell"},
	{regexp.MustCompile(`(?i)(?:^|[\s"'` + "`" + `(])-e[a-z]*\s+[A-Za-z0-9+/=]{24,}`), "PowerShell encoded command (-EncodedCommand)"},
}

func (r *cfg008) Check(t *Target) []finding.Finding {
	if t == nil || t.Settings == nil {
		return nil
	}

	var findings []finding.Finding
	for _, site := range commandSites(t.Settings) {
		if label, ok := matchReverseShell(site.Command); ok {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG008",
				Severity: finding.Error,
				File:     t.SettingsFile,
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
