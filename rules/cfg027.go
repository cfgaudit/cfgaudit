package rules

import (
	"regexp"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg027 struct{}

var CFG027 = &cfg027{}

func init() { All = append(All, CFG027) }

func (r *cfg027) ID() string { return "CFG027" }

// persistencePatterns match commands that install OS-level persistence — they
// survive reboots and new shell sessions and run outside Claude Code entirely.
var persistencePatterns = []struct {
	re    *regexp.Regexp
	label string
}{
	{regexp.MustCompile(`\bcrontab\b`), "crontab (cron job)"},
	{regexp.MustCompile(`/etc/cron`), "system cron directory"},
	{regexp.MustCompile(`(?:^|[\s/~"'$])\.(?:bashrc|zshrc|bash_profile|zprofile|bash_login|zshenv|profile)\b`), "shell startup file"},
	{regexp.MustCompile(`/etc/profile`), "shell startup file"},
	{regexp.MustCompile(`\bsystemctl\s+(?:--user\s+)?enable\b`), "systemd service enable"},
	{regexp.MustCompile(`/(?:etc|\.config)/systemd/`), "systemd unit directory"},
	{regexp.MustCompile(`\blaunchctl\s+(?:load|bootstrap|enable)\b`), "launchd agent"},
	{regexp.MustCompile(`\b(?:LaunchAgents|LaunchDaemons)\b`), "launchd plist directory"},
}

// Check flags command sites that install a persistence mechanism (cron, shell
// startup files, systemd, launchd). Scans hooks and command-running helpers.
func (r *cfg027) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	for _, site := range commandSites(t.Settings) {
		seen := map[string]bool{}
		for _, p := range persistencePatterns {
			if seen[p.label] || !p.re.MatchString(site.Command) {
				continue
			}
			seen[p.label] = true
			findings = append(findings, finding.Finding{
				RuleID:   "CFG027",
				Severity: finding.Error,
				File:     t.SettingsFile,
				Message: site.Label + " installs a persistence mechanism (" + p.label +
					") — it survives reboots and new sessions and runs outside Claude Code; a hook should never modify cron, shell startup files, or system services" + userScopeNote(t),
			})
		}
	}
	return findings
}
