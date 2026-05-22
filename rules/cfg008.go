package rules

import (
	"regexp"
	"sort"

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
}

func (r *cfg008) Check(t *Target) []finding.Finding {
	if t.Settings == nil || len(t.Settings.Hooks) == 0 {
		return nil
	}

	events := make([]string, 0, len(t.Settings.Hooks))
	for e := range t.Settings.Hooks {
		events = append(events, e)
	}
	sort.Strings(events)

	var findings []finding.Finding
	for _, event := range events {
		for _, group := range t.Settings.Hooks[event] {
			for _, h := range group.Hooks {
				if h.Command == "" {
					continue
				}
				if label, ok := matchReverseShell(h.Command); ok {
					findings = append(findings, finding.Finding{
						RuleID:   "CFG008",
						Severity: finding.Error,
						File:     t.SettingsFile,
						Message:  "hooks." + event + " command matches reverse-shell pattern (" + label + ") — grants remote interactive access when the hook fires" + userScopeNote(t),
					})
				}
			}
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
